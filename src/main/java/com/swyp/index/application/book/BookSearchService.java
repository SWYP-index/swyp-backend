package com.swyp.index.application.book;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Service;

import com.swyp.index.domain.book.Book;
import com.swyp.index.infrastructure.api.AladinApiClient;
import com.swyp.index.infrastructure.api.AladinSearchResponse;
import com.swyp.index.infrastructure.redis.SearchCacheAdapter;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.presentation.dto.book.BookSearchResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BookSearchService {

	private final BookRepository bookRepository;
	private final AladinApiClient aladinApiClient;
	private final SearchCacheAdapter cacheAdapter;

	public BookSearchResponse searchBooks(String title, int startIndex) {
		// 제목 + 페이지번호로 캐시 확인
		Optional<List<String>> cachedIsbns = cacheAdapter.getIsbnsCache(title, startIndex);

		if (cachedIsbns.isPresent()) {
			// 캐시에서 totalResults 조회
			int totalResults = cacheAdapter.getTotalResultsCache(title).orElse(0);

			// ISBN 리스트로 책 리스트 조회
			List<Book> books = bookRepository.findAllByIsbnIn((cachedIsbns.get()));

			return BookSearchResponse.of(books, startIndex, totalResults);
		}

		// 외부 API 호출
		AladinSearchResponse response = aladinApiClient.searchBooks(title, startIndex);

		if (response.isEmpty()) {
			return BookSearchResponse.empty();
		}

		// API 응답으로 ISBN 리스트 추출
		List<String> isbns = extractIsbns(response);

		// 제목 + 페이지번호, 총 검색 결과 수 로 캐시 저장
		saveCache(response, isbns);

		// API 응답 중 DB에 존재 하지 않는 정보 DB 저장
		saveBooksIfNotExists(response);

		List<Book> books = bookRepository.findAllByIsbnIn(isbns);

		return BookSearchResponse.of(books, startIndex, response.totalResults());
	}

	private List<String> extractIsbns(AladinSearchResponse aladinSearchResponse) {
		return aladinSearchResponse.items().stream()
			.map(AladinSearchResponse.BookItem::isbn)
			.toList();
	}

	private void saveBooksIfNotExists(AladinSearchResponse aladinSearchResponse) {
		List<String> isbnList = aladinSearchResponse.items().stream()
			.map(AladinSearchResponse.BookItem::isbn)
			.toList();

		List<String> existingIsbnList = bookRepository.findExistingIsbns(isbnList);
		Set<String> existingIsbnSet = new HashSet<>(existingIsbnList);

		List<Book> newBooks = aladinSearchResponse.items().stream()
			.filter(book -> !existingIsbnSet.contains(book.isbn()))
			.map(Book::from)
			.toList();

		bookRepository.saveAll(newBooks);
	}

	private void saveCache(AladinSearchResponse response, List<String> isbns) {
		cacheAdapter.saveIsbnsCache(response.title(), response.startIndex(), isbns);
		cacheAdapter.saveTotalResultsCache(response.title(), response.totalResults());
	}
}
