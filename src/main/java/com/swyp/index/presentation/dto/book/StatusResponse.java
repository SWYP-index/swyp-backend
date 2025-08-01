package com.swyp.index.presentation.dto.book;

import io.swagger.v3.oas.annotations.media.Schema;

public record StatusResponse(@Schema(description = "사용자의 해당 도서 상태", example = "NONE, WISH, READING, FINISHED") String status) {}
