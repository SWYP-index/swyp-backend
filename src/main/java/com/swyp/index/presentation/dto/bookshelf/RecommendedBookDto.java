package com.swyp.index.presentation.dto.bookshelf;


import com.swyp.index.domain.book.Book;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

import java.time.LocalDate;

@Getter
@Schema(description = "감정 기반 추천 도서 요약 DTO")
public class RecommendedBookDto {

    @Schema(description = "추천 감정 이름", example = "기쁨")
    private final String emotionName;

    @Schema(description = "ISBN", example = "9791191136979")
    private final String isbn;

    @Schema(description = "책 제목", example = "이처럼 사소한 것들")
    private final String title;

    @Schema(description = "저자", example = "클레어 키건")
    private final String author;

    @Schema(description = "표지 이미지 URL", example = "https://image.aladin.co.kr/product/31221/53/coversum/k392832962_1.jpg")
    private final String coverImageUrl;

    @Schema(description = "출판사", example = "다산책방")
    private final String publisher;

    @Schema(description = "카테고리/장르", example = "소설")
    private final String category;

    @Schema(description = "출판일", example = "2023-04-10")
    private final LocalDate publishedDate;

    private RecommendedBookDto(String emotionName, Book book) {
        this.emotionName = emotionName;
        this.isbn = book.getIsbn();
        this.title = book.getBookInfo().getTitle();
        this.author = book.getBookInfo().getAuthor();
        this.coverImageUrl = book.getBookInfo().getCoverImageUrl();
        this.publisher = book.getBookInfo().getPublisher();
        this.category = book.getBookInfo().getCategory();
        this.publishedDate = book.getBookInfo().getPublishedDate();
    }

    public static RecommendedBookDto of(String emotionName, Book book) {
        return new RecommendedBookDto(emotionName, book);
    }


}
