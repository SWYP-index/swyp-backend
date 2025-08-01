package com.swyp.index.presentation.dto.book;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.v3.oas.annotations.media.Schema;

public record BookResponse(
	@Schema(description = "사용자의 해당 도서 상태", example = "NULL, WISH, READING, FINISHED") String status,
	@JsonProperty("booK") BookDto bookDto) {
}
