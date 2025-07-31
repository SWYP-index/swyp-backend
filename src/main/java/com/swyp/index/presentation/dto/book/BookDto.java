package com.swyp.index.presentation.dto.book;

import java.util.List;

public record BookDto(BookInfoDto bookInfoDto, List<BookStatsDto> bookStatsDtos) {
}
