package com.swyp.index.domain.book;

import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Embeddable
@NoArgsConstructor(access = lombok.AccessLevel.PROTECTED)
@AllArgsConstructor
@Getter
public class BookInfo {

	private String title;

	private String author;

	@Column(length = 1000)
	private String description;

	private String publisher;

	private String coverImageUrl;

	private LocalDate publishedDate;

	private String category;
}
