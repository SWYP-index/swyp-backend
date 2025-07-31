package com.swyp.index.presentation.dto.book;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class BookEmotionSearchResponse {
	private int page;
	
	private List<BookDto> items;
}
