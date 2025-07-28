package com.swyp.index.domain.book;

import java.time.LocalDate;
import java.util.List;

import com.swyp.index.infrastructure.api.AladinSearchResponse;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor //빌더가 모든 필드를 받는 생성자를 사용할 수 있도록 추가
@Builder // 테스트에서 객체 생성을 쉽게 하기 위해 빌더 추가
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

	@OneToMany(mappedBy = "book", cascade = CascadeType.ALL, orphanRemoval = true)
	private List<BookStats> bookStats;

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