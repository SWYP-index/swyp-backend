package com.swyp.index.infrastructure.api;

import java.time.LocalDate;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AladinSearchResponse(@JsonProperty("item") List<BookItem> items,
								   @JsonProperty("query") String title,
								   int startIndex, int totalResults, int itemPerPage) {

	public static AladinSearchResponse empty() {
		return new AladinSearchResponse(List.of(), "", 0, 0, 0);
	}

	public boolean isEmpty() {
		return items == null || items.isEmpty();
	}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record BookItem(
		String title,
		String isbn,
		String isbn13,
		String author,
		String description,
		@JsonFormat(pattern = "yyyy-MM-dd") LocalDate pubDate,
		String publisher,
		String categoryName,
		@JsonProperty("cover") String coverImageUrl
	) {}

}

