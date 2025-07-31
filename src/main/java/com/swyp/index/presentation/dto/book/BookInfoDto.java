package com.swyp.index.presentation.dto.book;

import java.time.LocalDate;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookInfo;

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
		response.isbn = book.getIsbn();
		response.totalCount = book.getTotalCount();

		BookInfo bookInfo = book.getBookInfo();

		response.title = bookInfo.getTitle();
		response.author = bookInfo.getAuthor();
		response.coverImageUrl = bookInfo.getCoverImageUrl();
		response.publishedDate = bookInfo.getPublishedDate();
		response.description = bookInfo.getDescription();
		response.publisher = bookInfo.getPublisher();
		response.category = bookInfo.getCategory();

		return response;
	}
}