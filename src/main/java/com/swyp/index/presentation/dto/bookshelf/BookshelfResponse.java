package com.swyp.index.presentation.dto.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.presentation.dto.book.BookResponse;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
public class BookshelfResponse {
    private Long bookshelfId;        // Bookshelf PK
    private String status;           // WISH, READING, FINISHED
    private LocalDateTime addedAt;   // createdAt
    private LocalDateTime finishedAt; // finishedAt (완독 시 기록)
    private BookResponse book;       // 책 정보

    public static BookshelfResponse of(Bookshelf shelf) {
        BookshelfResponse dto = new BookshelfResponse();
        dto.bookshelfId = shelf.getId();
        dto.status      = shelf.getStatus().name();
        dto.addedAt     = shelf.getCreatedAt();
        dto.finishedAt  = shelf.getFinishedAt();
        dto.book        = BookResponse.from(shelf.getBook());
        return dto;
    }
}
