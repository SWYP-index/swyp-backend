package com.swyp.index.presentation.dto.book;

import java.util.List;

import com.swyp.index.domain.book.Book;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class BookTitleSearchResponse {
	private int page;
	private int totalResults;

	private List<BookInfoDto> items;

	public static BookTitleSearchResponse of(List<Book> books, int page, int totalResults) {
		BookTitleSearchResponse response = new BookTitleSearchResponse();

		response.items = books.stream()
				.map(BookInfoDto::from)
				.toList();

		response.page = page;
		response.totalResults = totalResults;

		return response;
	}

	public static BookTitleSearchResponse empty() {
		BookTitleSearchResponse response = new BookTitleSearchResponse();

		response.items = List.of();
		response.page = 0;
		response.totalResults = 0;

		return response;
	}
}