package com.swyp.index.presentation.dto.bookshelf;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@Schema(description = "책상 전체 조회 응답 DTO (읽는 중 + 추천도서)", example = """
{
  "readingBooks": [
    {
      "isbn": "9788956604996",
      "title": "총, 균, 쇠",
      "author": "재레드 다이아몬드",
      "coverImageUrl": "https://image.aladin.co.kr/product/123/456/cover.jpg"
    }
  ],
  "recommendedBooks": [
    {
      "emotionName": "기쁨",
      "isbn": "9788996991342",
      "title": "인간 본성에 대하여",
      "author": "에드워드 윌슨",
      "coverImageUrl": "https://image.aladin.co.kr/product/987/654/cover.jpg",
      "publisher": "사이언스북스",
      "category": "인문학",
      "publishedDate": "2021-05-17"
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
