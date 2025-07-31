package com.swyp.index.domain.book;

import static com.swyp.index.domain.bookshelf.RecordCreatedEvent.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.api.AladinSearchResponse.BookItem;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapKey;
import jakarta.persistence.OneToMany;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
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

	@Embedded
	private BookInfo bookInfo;

	private Long totalCount = 0L;

	private Long totalEmotionScoreSum = 0L;

	public static Book from(BookItem bookItem) {
		Book book = Book.builder()
			.isbn(bookItem.isbn())
			.bookInfo(new BookInfo(bookItem.title(), bookItem.author(), bookItem.description(), bookItem.publisher(),
				bookItem.coverImageUrl(), bookItem.pubDate(), bookItem.categoryName()))
			.build();

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

	public void addRecordToStats(List<RecordCreatedEventEmotion> emotions) {
		emotions.forEach(emotion -> {
			BookStats bookStats = bookStatsMap.get(emotion.emotionId());

			if (bookStats == null) {
				throw new CustomException(ErrorCode.BOOK_STATS_NOT_FOUND);
			}

			totalCount += 1;
			totalEmotionScoreSum += emotion.score();

			bookStats.record(emotion.score());
		});
	}
}