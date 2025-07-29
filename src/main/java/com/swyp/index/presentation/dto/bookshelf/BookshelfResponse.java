package com.swyp.index.presentation.dto.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelves;
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

    public static BookshelfResponse of(Bookshelves shelf) {
        BookshelfResponse br = new BookshelfResponse();
        br.bookshelfId = shelf.getId();
        br.status      = shelf.getStatus().name();
        br.addedAt     = shelf.getCreatedAt();
        br.finishedAt  = shelf.getFinishedAt();
        br.book        = BookResponse.from(shelf.getBook());
        return br;
    }
}
