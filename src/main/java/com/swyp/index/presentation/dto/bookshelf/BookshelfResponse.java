package com.swyp.index.presentation.dto.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.presentation.dto.book.BookInfoDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@Schema(description = "책장 도서 정보 응답 DTO")
public class BookshelfResponse {
    @Schema(description = "책장 아이템의 고유 ID", example = "101")
    private Long bookshelfId;        // Bookshelf PK
    @Schema(description = "독서 상태 (WISH, READING, FINISHED)", example = "FINISHED")
    private String status;           // WISH, READING, FINISHED
    @Schema(description = "독서 시작일", example = "2025-07-31T00:21:16")
    private LocalDateTime createdAt;   // createdAt
    @Schema(description = "독서 완료일 (완독 상태가 아닐 경우 null)", example = "null")
    private LocalDateTime finishedAt; // finishedAt (완독 시 기록)
    @Schema(description = "책 상세 정보")
    private BookInfoDto book;       // 책 정보

    public static BookshelfResponse of(Bookshelf shelf) {
        BookshelfResponse br = new BookshelfResponse();
        br.bookshelfId = shelf.getId();
        br.status = shelf.getStatus().name();
        br.createdAt = shelf.getCreatedAt();
        br.finishedAt = shelf.getFinishedAt();
        br.book = BookInfoDto.from(shelf.getBook());
        return br;
    }
}
