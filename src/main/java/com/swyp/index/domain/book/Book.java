package com.swyp.index.domain.book;

import java.time.LocalDate;

import com.swyp.index.infrastructure.api.AladinSearchResponse;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Book {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, nullable = false)
	private String isbn;

	private String title;

	private String author;

	@Column(length = 1000)
	private String description;

	private String publisher;

	private String coverImageUrl;

	private LocalDate publishedDate;

	private String category;

	@OneToOne(mappedBy = "book", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private BookStats bookStats;

	public static Book from(AladinSearchResponse.BookItem bookItem) {
		Book book = new Book();

		book.isbn = bookItem.isbn();
		book.title = bookItem.title();
		book.author = bookItem.author();
		book.description = bookItem.description();
		book.publisher = bookItem.publisher();
		book.coverImageUrl = bookItem.coverImageUrl();
		book.publishedDate = bookItem.pubDate();
		book.category = bookItem.categoryName();

		return book;
	}
}