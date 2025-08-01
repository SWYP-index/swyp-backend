package com.swyp.index.presentation.dto.book;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class BookEmotionSearchResponse {

	@Schema(description = "현재 페이지 번호", example = "2")
	private int page;
	
	private List<BookDto> books;
}
