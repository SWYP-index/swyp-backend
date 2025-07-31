package com.swyp.index.application.book;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookStats;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.api.AladinApiClient;
import com.swyp.index.infrastructure.api.AladinSearchResponse;
import com.swyp.index.infrastructure.redis.SearchCacheAdapter;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.EmotionRepository;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.book.BookEmotionSearchResponse;
import com.swyp.index.presentation.dto.book.BookInfoDto;
import com.swyp.index.presentation.dto.book.BookResponse;
import com.swyp.index.presentation.dto.book.BookStatsDto;
import com.swyp.index.presentation.dto.book.BookTitleSearchResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BookQueryService {

	private final AladinApiClient aladinApiClient;
	private final SearchCacheAdapter cacheAdapter;
	private final BookRepository bookRepository;
	private final BookshelfRepository bookshelfRepository;
	private final EmotionRepository emotionRepository;

	@Transactional(readOnly = true)
	public BookEmotionSearchResponse searchBooksByEmotion(String emotionName, int startIndex) {
		Emotion emotion = emotionRepository.findByName(emotionName)
			.orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));

		List<Book> books = bookRepository.findBooksByEmotionIdOrderByEmotionScoreSumDesc(emotion.getId(),
			PageRequest.of(startIndex - 1, 10));

		List<BookDto> bookDtos = new ArrayList<>();

		for (Book book: books) {
			List<BookStats> bookStats = bookRepository.findTopByBookIdOrderByEmotionScoreSumDesc(
				book.getId(), PageRequest.of(0, 3));

			bookDtos.add(convertToBookDto(book, bookStats));
		}

		return new BookEmotionSearchResponse(startIndex, bookDtos);
	}

	public BookTitleSearchResponse searchBooksByTitle(String title, int startIndex) {
		Optional<List<String>> cachedIsbns = cacheAdapter.getIsbnsCache(title, startIndex);

		if (cachedIsbns.isPresent()) {
			int totalResults = cacheAdapter.getTotalResultsCache(title).orElse(0);

			List<Book> books = bookRepository.findAllByIsbnIn((cachedIsbns.get()));

			List<BookDto> bookDtos = new ArrayList<>();

			for (Book book: books) {
				List<BookStats> bookStats = bookRepository.findTopByBookIdOrderByEmotionScoreSumDesc(
					book.getId(), PageRequest.of(0, 3));

				bookDtos.add(convertToBookDto(book, bookStats));
			}

			return new BookTitleSearchResponse(startIndex, totalResults, bookDtos);
		}

		// 외부 API로 책 검색
		AladinSearchResponse response = aladinApiClient.searchBooks(title, startIndex);

		if (response.isEmpty()) {
			return BookTitleSearchResponse.empty();
		}

		List<String> isbns = extractIsbns(response);

		cacheAdapter.saveCache(response, isbns);
		saveBooksIfNotExists(response);

		List<Book> books = bookRepository.findAllByIsbnIn(isbns);

		List<BookDto> bookDtos = new ArrayList<>();

		for (Book book: books) {
			List<BookStats> bookStats = bookRepository.findTopByBookIdOrderByEmotionScoreSumDesc(
				book.getId(), PageRequest.of(0, 3));

			bookDtos.add(convertToBookDto(book, bookStats));
		}

		return new BookTitleSearchResponse(startIndex, response.totalResults(), bookDtos);
	}

	@Transactional(readOnly = true)
	public BookResponse getBookDetail(User user, String isbn) {
		Book book = bookRepository.findByIsbn(isbn)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		List<BookStats> BookStats = bookRepository.findAllByBookIdOrderByEmotionScoreSumDesc(
			book.getId());

		BookDto bookDto = convertToBookDto(book, BookStats);

		Bookshelf bookshelf = bookshelfRepository.findByUserAndBook(user, book)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

		return new BookResponse(bookshelf.getStatus().name(), bookDto);
	}

	private BookDto convertToBookDto(Book book, List<BookStats> bookStats) {
		Long totalSum = book.getTotalEmotionScoreSum();

		List<BookStatsDto> bookStatsDtos = bookStats.stream().map(bs -> {
			double percentage = 0.0;

			if (totalSum != null && totalSum > 0) {
				percentage = (double)bs.getEmotionScoreSum() / totalSum * 100;
			}

			Emotion emotion = emotionRepository.findById(bs.getEmotionId())
				.orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));

			return new BookStatsDto(bs.getEmotionId(), emotion.getName(), bs.getEmotionScoreSum(), percentage);
		}).toList();

		return new BookDto(BookInfoDto.from(book), bookStatsDtos);
	}

	// ISBN 리스트 추출
	private List<String> extractIsbns(AladinSearchResponse aladinSearchResponse) {
		return aladinSearchResponse.items().stream().map(AladinSearchResponse.BookItem::isbn).toList();
	}

	// DB에 존재하지 않는 책 정보만 필터링 후 저장
	private void saveBooksIfNotExists(AladinSearchResponse aladinSearchResponse) {
		List<String> isbnList = aladinSearchResponse.items().stream().map(AladinSearchResponse.BookItem::isbn).toList();

		List<String> existingIsbnList = bookRepository.findExistingIsbns(isbnList);
		Set<String> existingIsbnSet = new HashSet<>(existingIsbnList);

		List<Book> newBooks = aladinSearchResponse.items()
			.stream()
			.filter(book -> !existingIsbnSet.contains(book.isbn()))
			.map(Book::from)
			.toList();

		bookRepository.saveAll(newBooks);
	}
}
