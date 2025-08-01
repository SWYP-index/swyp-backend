package com.swyp.index.presentation.dto.book;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BookTitleSearchResponse {

	@Schema(description = "현재 페이지 번호", example = "2")
	private int page;

	@Schema(description = "총 검색 결과 수", example = "162")
	private int totalResults;

	private List<BookDto> books;

	public static BookTitleSearchResponse empty() {
		return BookTitleSearchResponse.builder()
			.page(0)
			.totalResults(0)
			.books(List.of())
			.build();
	}
}