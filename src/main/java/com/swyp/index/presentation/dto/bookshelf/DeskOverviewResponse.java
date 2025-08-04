package com.swyp.index.presentation.dto.bookshelf;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@Schema(description = "책상 전체 조회 응답 DTO (읽는 중 + 추천도서")
public record DeskOverviewResponse(

        @Schema(description = "현재 책상에 담긴 읽는 중 도서 목록")
        List<BookshelfSummaryDto> readingBooks,

        @Schema(description = "감정 기반 추천 도서 목록")
        List<RecommendedBookDto> recommendedBooks
) {}
