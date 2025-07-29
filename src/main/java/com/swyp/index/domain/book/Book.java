package com.swyp.index.domain.book;

import static com.swyp.index.domain.bookshelf.RecordCreatedEvent.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.swyp.index.domain.bookshelf.RecordCreatedEvent;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.api.AladinSearchResponse.BookItem;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapKey;
import jakarta.persistence.OneToMany;
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

	@OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
	@JoinColumn(name = "book_id")
	@MapKey(name = "emotionId")
	private Map<Long, BookStats> bookStatsMap;

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

	public static Book from(BookItem bookItem) {
		Book book = new Book();

		book.isbn = bookItem.isbn();
		book.title = bookItem.title();
		book.author = bookItem.author();
		book.description = bookItem.description();
		book.publisher = bookItem.publisher();
		book.coverImageUrl = bookItem.coverImageUrl();
		book.publishedDate = bookItem.pubDate();
		book.category = bookItem.categoryName();

		book.initializeBookStats();

		return book;
	}

	private void initializeBookStats() {
		this.bookStatsMap = new HashMap<>();

		for (long emotionId = 1; emotionId <= 20; emotionId++) {
			BookStats stats = new BookStats();
			stats.setEmotionId(emotionId);

			this.bookStatsMap.put(emotionId, stats);
		}
	}

	public void updateStats(List<RecordCreatedEventEmotion> emotions) {
		emotions.forEach(emotion -> {
			BookStats bookStats = bookStatsMap.get(emotion.emotionId());

			if (bookStats == null) {
				throw new CustomException(ErrorCode.BOOK_STATS_NOT_FOUND);
			}

			bookStats.record(emotion.score());
		});
	}
}