package com.swyp.index.application.book;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookStats;
import com.swyp.index.infrastructure.api.AladinApiClient;
import com.swyp.index.infrastructure.api.AladinSearchResponse;
import com.swyp.index.infrastructure.redis.SearchCacheAdapter;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.book.BookSearchResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BookCommandService {

	private final AladinApiClient aladinApiClient;
	private final SearchCacheAdapter cacheAdapter;
	private final BookRepository bookRepository;

	public BookSearchResponse fetchBooksByTitleAndStoreIfAbsent(String title, int startIndex) {
		Optional<List<String>> cachedIsbns = cacheAdapter.getIsbnsCache(title, startIndex);

		if (cachedIsbns.isPresent()) {
			int totalResults = cacheAdapter.getTotalResultsCache(title).orElse(0);

			List<Book> books = bookRepository.findAllByIsbnIn((cachedIsbns.get()));

			List<BookDto> bookDtos = convertBookToDto(books);

			return new BookSearchResponse(startIndex, totalResults, bookDtos);
		}

		// 외부 API로 책 검색
		AladinSearchResponse response = aladinApiClient.searchBooks(title, startIndex);

		if (response.isEmpty()) {
			return BookSearchResponse.empty();
		}

		List<String> isbns = extractIsbns(response);

		cacheAdapter.saveCache(response, isbns);
		saveBooksIfNotExists(response);

		List<Book> books = bookRepository.findAllByIsbnIn(isbns);

		List<BookDto> bookDtos = convertBookToDto(books);

		return new BookSearchResponse(startIndex, response.totalResults(), bookDtos);
	}

	private List<BookDto> convertBookToDto(List<Book> books) {
		List<BookDto> bookDtos = new ArrayList<>();

		for (Book book: books) {
			List<BookStats> bookStats = bookRepository.findTopByBookIdOrderByEmotionScoreSumDescGreaterThanZero(
				book.getId(), PageRequest.of(0, 3));

			bookDtos.add(BookDto.from(book, bookStats));
		}

		return bookDtos;
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
