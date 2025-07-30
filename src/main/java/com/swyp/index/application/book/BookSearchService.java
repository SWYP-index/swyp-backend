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
import com.swyp.index.infrastructure.repository.EmotionRepository;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.book.BookEmotionSearchResponse;
import com.swyp.index.presentation.dto.book.BookInfoDto;
import com.swyp.index.presentation.dto.book.BookTitleSearchResponse;
import com.swyp.index.presentation.dto.book.BookStatsDto;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BookSearchService {

	private final AladinApiClient aladinApiClient;
	private final SearchCacheAdapter cacheAdapter;
	private final BookRepository bookRepository;
	private final EmotionRepository emotionRepository;

	public BookEmotionSearchResponse searchBooksByEmotion(String emotion, int startIndex) {
		int pageSize = 10;

		List<Book> books = bookRepository.findBooksByEmotionIdOrderByTotalEmotionScoreDesc(emotionRepository.findByName(emotion).get().getId(), PageRequest.of(startIndex - 1, pageSize));

		List<BookDto> bookDtos = new ArrayList<>();

		for (Book book : books) {
			List<BookStats> top3Stats = bookRepository.findTopByBookIdOrderByTotalEmotionScoreDesc(book.getId(), PageRequest.of(0, 3));

			Long totalSum = book.getTotalEmotionScoreSum();

			List<BookStatsDto> bookStatsDtos = top3Stats.stream().map(bs -> {
				double percentage = 0.0;

				if (totalSum != null && totalSum > 0) {
					percentage = (double)bs.getTotalEmotionScore() / totalSum * 100;
				}

				return new BookStatsDto(bs.getId(), bs.getEmotionId(),
					emotionRepository.findById(bs.getEmotionId()).get().getName(), percentage);
			}).toList();


			bookDtos.add(new BookDto(BookInfoDto.from(book), bookStatsDtos));
		}

		// 감정별 책 검색 로직은 아직 구현되지 않았으므로, 임시로 빈 응답 반환
		return new BookEmotionSearchResponse(startIndex, bookDtos);
	}

	public BookTitleSearchResponse searchBooks(String title, int startIndex) {
		// 제목 + 페이지번호로 캐시 확인
		Optional<List<String>> cachedIsbns = cacheAdapter.getIsbnsCache(title, startIndex);

		if (cachedIsbns.isPresent()) {
			// 캐시에서 totalResults 조회
			int totalResults = cacheAdapter.getTotalResultsCache(title).orElse(0);

			// ISBN 리스트로 책 리스트 조회
			List<Book> books = bookRepository.findAllByIsbnIn((cachedIsbns.get()));

			return BookTitleSearchResponse.of(books, startIndex, totalResults);
		}

		// 외부 API 호출
		AladinSearchResponse response = aladinApiClient.searchBooks(title, startIndex);

		if (response.isEmpty()) {
			return BookTitleSearchResponse.empty();
		}

		List<String> isbns = extractIsbns(response);

		saveCache(response, isbns);

		saveBooksIfNotExists(response);

		List<Book> books = bookRepository.findAllByIsbnIn(isbns);

		return BookTitleSearchResponse.of(books, startIndex, response.totalResults());
	}

	// ISBN 리스트 추출
	private List<String> extractIsbns(AladinSearchResponse aladinSearchResponse) {
		return aladinSearchResponse.items().stream().map(AladinSearchResponse.BookItem::isbn).toList();
	}

	// DB에 존재하지 않는 책 정보만 필터링 후  저장
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

	// 제목 + 페이지번호, 총 검색 결과 수 로 캐시 저장
	private void saveCache(AladinSearchResponse response, List<String> isbns) {
		cacheAdapter.saveIsbnsCache(response.title(), response.startIndex(), isbns);
		cacheAdapter.saveTotalResultsCache(response.title(), response.totalResults());
	}
}
