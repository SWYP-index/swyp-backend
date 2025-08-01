package com.swyp.index.presentation.dto.bookshelf;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import lombok.Getter;

import java.time.LocalDate;

@Getter
public class BookshelfSummaryDto {
    private final Long bookshelfId;
    private final String status;
    private final String isbn;
    private final String title;
    private final String author;
    private final String coverImageUrl;
    private final String publisher;
    private final String category;
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
