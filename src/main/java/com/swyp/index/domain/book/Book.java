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
	@Builder.Default
	private Map<Long, BookStats> bookStatsMap = new HashMap<>();

	@Column(unique = true, nullable = false)
	private String isbn;

	private String isbn13;

	@Embedded
	private BookInfo bookInfo;

	public static Book from(BookItem bookItem) {
		return Book.builder()
			.isbn(bookItem.isbn())
			.isbn13(bookItem.isbn13())
			.bookInfo(new BookInfo(bookItem.title(), bookItem.author(), bookItem.description(), bookItem.publisher(),
				bookItem.coverImageUrl(), bookItem.pubDate(), bookItem.categoryName()))
			.build();
	}

	public void initializeStatsIfAbsent() {
		if (this.bookStatsMap.isEmpty()) {
			for (long emotionId = 1; emotionId <= 20; emotionId++) {
				BookStats stats = new BookStats();
				stats.setEmotionId(emotionId);

				this.bookStatsMap.put(emotionId, stats);
			}
		}
	}

	public void addRecordToStats(List<RecordCreatedEventEmotion> emotions) {
		emotions.forEach(emotion -> {
			BookStats bookStats = bookStatsMap.get(emotion.emotionId());

			if (bookStats == null) {
				throw new CustomException(ErrorCode.BOOK_STATS_NOT_FOUND);
			}

			int score = emotion.score();

			validateEmotionScore(score);

			bookStats.record(score);
		});
	}

	public long getTotalEmotionCount() {
		return bookStatsMap.values().stream()
			.mapToLong(BookStats::getEmotionCount)
			.sum();
	}

	public long getTotalEmotionScoreSum() {
		return bookStatsMap.values().stream()
			.mapToLong(BookStats::getEmotionScoreSum)
			.sum();
	}

	private void validateEmotionScore(int score) {
		if (score < 1 || score > 10) {
			throw new CustomException(ErrorCode.INVALID_INPUT_VALUE);
		}
	}
}