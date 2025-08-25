package com.swyp.index.presentation.dto.wishlist;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookInfo;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Getter
@Builder
@Schema(description = "찜한 도서 목록 조회용 응답 DTO")
public class WishlistResponseDto {

    // 찜한 책에는 bookshelfId나 status가 없으므로 해당 필드는 제외합니다.
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

    /**
     * Wishlist 조회를 위해 Book 엔티티로부터 직접 DTO를 생성합니다.
     */
    public static WishlistResponseDto from(Book book) {
        BookInfo info = book.getBookInfo();
        return WishlistResponseDto.builder()
                .isbn(book.getIsbn())
                .title(info.getTitle())
                .author(info.getAuthor())
                .coverImageUrl(info.getCoverImageUrl())
                .publisher(info.getPublisher())
                .category(info.getCategory())
                .publishedDate(info.getPublishedDate())
                .build();
    }
}