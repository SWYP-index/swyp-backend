package com.swyp.index.presentation.dto.book;

import java.time.LocalDate;

import com.swyp.index.domain.book.Book;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class BookResponse {
	private Long bookId;
	private String title;
	private String isbn;
	private String author;
	private String coverImageUrl;
	private LocalDate publishedDate;
	private String description;
	private String publisher;
	private String category;

	public static BookResponse from(Book book) {
		BookResponse response = new BookResponse();

		response.bookId = book.getId();
		response.title = book.getTitle();
		response.isbn = book.getIsbn();
		response.author = book.getAuthor();
		response.coverImageUrl = book.getCoverImageUrl();
		response.publishedDate = book.getPublishedDate();
		response.description = book.getDescription();
		response.publisher = book.getPublisher();
		response.category = book.getCategory();

		return response;
	}
}