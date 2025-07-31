package com.swyp.index.presentation.dto.book;

import java.time.LocalDate;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookInfo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@Builder
@AllArgsConstructor
public class BookInfoDto {

	private Long bookId;
	private String isbn;
	private String title;
	private String author;
	private String coverImageUrl;
	private LocalDate publishedDate;
	private String description;
	private String publisher;
	private String category;
	private Long totalCount;

	public static BookInfoDto from(Book book) {
		BookInfo bookInfo = book.getBookInfo();

		return BookInfoDto.builder()
			.bookId(book.getId())
			.isbn(book.getIsbn())
			.title(bookInfo.getTitle())
			.author(bookInfo.getAuthor())
			.coverImageUrl(bookInfo.getCoverImageUrl())
			.publishedDate(bookInfo.getPublishedDate())
			.description(bookInfo.getDescription())
			.publisher(bookInfo.getPublisher())
			.category(bookInfo.getCategory())
			.totalCount(book.getTotalCount())
			.build();
	}
}