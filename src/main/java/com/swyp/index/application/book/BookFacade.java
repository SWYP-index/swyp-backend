package com.swyp.index.application.book;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.swyp.index.infrastructure.api.AladinApiClient;
import com.swyp.index.infrastructure.api.AladinSearchResponse;
import com.swyp.index.infrastructure.redis.SearchCacheAdapter;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.book.BookSearchResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BookFacade {

	private final AladinApiClient aladinApiClient;
	private final SearchCacheAdapter cacheAdapter;
	private final BookQueryService bookQueryService;
	private final BookCommandService bookCommandService;

	public BookSearchResponse fetchBooksByTitleAndStoreIfAbsent(String title, int startIndex) {
		Optional<List<String>> cachedIsbns = cacheAdapter.getIsbnsCache(title, startIndex);

		if (cachedIsbns.isPresent()) {
			int totalResults = cacheAdapter.getTotalResultsCache(title).orElse(0);

			List<BookDto> bookDtos = bookQueryService.getBookDtosByIsbnIn(cachedIsbns.get());

			return new BookSearchResponse(startIndex, totalResults, bookDtos);
		}

		// 외부 API로 책 검색
		AladinSearchResponse response = aladinApiClient.searchBooks(title, startIndex);

		if (response.isEmpty()) {
			return BookSearchResponse.empty();
		}

		List<String> isbns = extractIsbns(response);

		cacheAdapter.saveCache(response, isbns);
		bookCommandService.saveBooksIfNotExists(response);

		List<BookDto> bookDtos = bookQueryService.getBookDtosByIsbnIn(isbns);

		return new BookSearchResponse(startIndex, response.totalResults(), bookDtos);
	}

	private List<String> extractIsbns(AladinSearchResponse aladinSearchResponse) {
		return aladinSearchResponse.items().stream().map(AladinSearchResponse.BookItem::isbn).toList();
	}
}
