package com.swyp.index.presentation.dto.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelf;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
@Schema(description = "책장 도서 요약 정보")
public class BookshelfSummaryResponse {
    private Long bookId;
    private String title;
    private String author;
    private String coverImage;
    private LocalDateTime createdAt;

    // 엔티티를 DTO로 변환하는 정적 팩토리 메소드
    public static BookshelfSummaryResponse from(Bookshelf bookshelf) {
        return new BookshelfSummaryResponse(
                bookshelf.getBook().getId(),
                bookshelf.getBook().getTitle(),
                bookshelf.getBook().getAuthor(),
                bookshelf.getBook().getCoverImageUrl(),
                bookshelf.getCreatedAt()
        );
    }
}
