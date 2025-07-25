package com.swyp.index.presentation.dto.book;

import java.util.List;

import com.swyp.index.domain.book.Book;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class BookSearchResponse {
	private int page;
	private int totalResults;

	private List<BookResponse> items;

	public static BookSearchResponse of(List<Book> books, int page, int totalResults) {
		BookSearchResponse response = new BookSearchResponse();

		response.items = books.stream()
				.map(BookResponse::from)
				.toList();

		response.page = page;
		response.totalResults = totalResults;

		return response;
	}

	public static BookSearchResponse empty() {
		BookSearchResponse response = new BookSearchResponse();

		response.items = List.of();
		response.page = 0;
		response.totalResults = 0;

		return response;
	}
}