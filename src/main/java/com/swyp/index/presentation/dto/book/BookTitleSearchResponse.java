package com.swyp.index.presentation.dto.book;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@AllArgsConstructor
public class BookTitleSearchResponse {

	private int page;
	private int totalResults;
	private List<BookDto> items;

	public static BookTitleSearchResponse empty() {
		BookTitleSearchResponse response = new BookTitleSearchResponse();

		response.page = 0;
		response.totalResults = 0;
		response.items = List.of();

		return response;
	}
}