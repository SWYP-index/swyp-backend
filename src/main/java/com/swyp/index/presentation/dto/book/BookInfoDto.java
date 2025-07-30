package com.swyp.index.presentation.dto.book;

import java.time.LocalDate;

import com.swyp.index.domain.book.Book;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class BookInfoDto {
	private Long bookId;
	private String title;
	private String isbn;
	private String author;
	private String coverImageUrl;
	private LocalDate publishedDate;
	private String description;
	private String publisher;
	private String category;
	private Long totalCount;

	public static BookInfoDto from(Book book) {
		BookInfoDto response = new BookInfoDto();

		response.bookId = book.getId();
		response.title = book.getTitle();
		response.isbn = book.getIsbn();
		response.author = book.getAuthor();
		response.coverImageUrl = book.getCoverImageUrl();
		response.publishedDate = book.getPublishedDate();
		response.description = book.getDescription();
		response.publisher = book.getPublisher();
		response.category = book.getCategory();
		response.totalCount = book.getTotalCount();

		return response;
	}
}