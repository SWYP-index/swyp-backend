package com.swyp.index.presentation.dto.book;

import java.time.LocalDate;

import com.swyp.index.domain.book.Book;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@Schema(description = "도서 정보 응답 DTO")
public class BookResponse {
	@Schema(description = "도서 고유 ID", example = "1")
	private Long bookId;
	@Schema(description = "제목", example = "데미안")
	private String title;
	@Schema(description = "ISBN 13자리", example = "9788937460476")
	private String isbn;
	@Schema(description = "저자", example = "헤르만 헤세")
	private String author;
	@Schema(description = "표지 이미지 URL", example = "https://image.aladin.co.kr/product/26/0/coversum/s742633278_2.jpg")
	private String coverImageUrl;
	@Schema(description = "출판일", example = "1919-01-01")
	private LocalDate publishedDate;
	@Schema(description = "책 소개", example = "에밀 싱클레어라는 인물의 성장에 대한 이야기...")
	private String description;
	@Schema(description = "출판사", example = "민음사")
	private String publisher;
	@Schema(description = "카테고리/장르", example = "고전소설")
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