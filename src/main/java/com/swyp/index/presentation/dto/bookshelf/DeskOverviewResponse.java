package com.swyp.index.presentation.dto.bookshelf;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@Schema(description = "책상 전체 조회 응답 DTO (읽는 중 + 추천도서)", example = """
{
  "readingBooks": [
    {
      "bookshelfId": 101,
      "status": "READING",
      "isbn": "9791191136979",
      "title": "이처럼 사소한 것들",
      "author": "클레어 키건",
      "coverImageUrl": "https://image.aladin.co.kr/product/31221/53/coversum/k392832962_1.jpg",
      "publisher": "다산책방",
      "category": "소설",
      "publishedDate": "2023-04-10"
    }
  ],
  "recommendedBooks": [
    {
      "emotionName": "기쁨",
      "isbn": "9791191136979",
      "title": "이처럼 사소한 것들",
      "author": "클레어 키건",
      "coverImageUrl": "https://image.aladin.co.kr/product/31221/53/coversum/k392832962_1.jpg",
      "publisher": "다산책방",
      "category": "소설",
      "publishedDate": "2023-04-10"
    }
  ]
}
""")
public record DeskOverviewResponse(

        @Schema(description = "현재 책상에 담긴 읽는 중 도서 목록")
        List<BookshelfSummaryDto> readingBooks,

        @Schema(description = "감정 기반 추천 도서 목록")
        List<RecommendedBookDto> recommendedBooks
) {}
