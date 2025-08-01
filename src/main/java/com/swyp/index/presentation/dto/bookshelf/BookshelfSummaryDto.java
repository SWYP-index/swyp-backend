package com.swyp.index.presentation.dto.bookshelf;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

import java.time.LocalDate;

@Getter
@Schema(description = "책상, 책장 목록 조회용 요약 DTO")
public class BookshelfSummaryDto {
    @Schema(description = "책장 아이템 ID", example = "101")
    private final Long bookshelfId;
    @Schema(description = "독서 상태 (책상)READING, (책장)FINISHED", example = "READING")
    private final String status;
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

    private BookshelfSummaryDto(Bookshelf shelf) {
        Book book = shelf.getBook();
        this.bookshelfId = shelf.getId();
        this.status = shelf.getStatus().name();
        this.isbn = book.getIsbn();
        this.title = book.getBookInfo().getTitle();
        this.author = book.getBookInfo().getAuthor();
        this.coverImageUrl = book.getBookInfo().getCoverImageUrl();
        this.publisher = book.getBookInfo().getPublisher();
        this.category = book.getBookInfo().getCategory();
        this.publishedDate = book.getBookInfo().getPublishedDate();
    }

    public static BookshelfSummaryDto from(Bookshelf shelf) {
        return new BookshelfSummaryDto(shelf);
    }

}
