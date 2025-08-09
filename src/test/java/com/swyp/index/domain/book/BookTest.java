package com.swyp.index.domain.book;

import static org.assertj.core.api.Assertions.*;

import java.util.List;
import java.util.stream.LongStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.swyp.index.domain.bookshelf.RecordCreatedEvent.RecordCreatedEventEmotion;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;

class BookTest {

	private Book book;

	@BeforeEach
	void setUp() {
		book = BookFixture.createBook("0000000000");
	}

	@Test
	public void initializeStatsIfAbsent() {
		assertThat(book.getBookStatsMap()).hasSize(20);
		assertThat(book.getBookStatsMap().keySet()).containsExactlyInAnyOrder(
			LongStream.rangeClosed(1, 20).boxed().toArray(Long[]::new)
		);
	}

	@Test
	void addRecordToStats() {
		List<RecordCreatedEventEmotion> emotions = List.of(
			new RecordCreatedEventEmotion(1L, 1),
			new RecordCreatedEventEmotion(1L, 2),
			new RecordCreatedEventEmotion(2L, 3)
		);

		book.addRecordToStats(emotions);

		BookStats stats1 = book.getBookStatsMap().get(1L);
		assertThat(stats1.getEmotionCount()).isEqualTo(2);
		assertThat(stats1.getEmotionScoreSum()).isEqualTo(3);
		assertThat(stats1.getEmotionScoreAverage()).isEqualTo(1.5);

		BookStats stats2 = book.getBookStatsMap().get(2L);
		assertThat(stats2.getEmotionCount()).isEqualTo(1);
		assertThat(stats2.getEmotionScoreSum()).isEqualTo(3);
		assertThat(stats2.getEmotionScoreAverage()).isEqualTo(3.0);

		assertThat(book.getTotalEmotionCount()).isEqualTo(3);
		assertThat(book.getTotalEmotionScoreSum()).isEqualTo(6);
	}

	@Test
	void addRecordToStats_Fail() {
		List<RecordCreatedEventEmotion> emotions = List.of(
			new RecordCreatedEventEmotion(1L, 0),
			new RecordCreatedEventEmotion(2L, 11)
		);

		assertThatThrownBy(() -> book.addRecordToStats(emotions))
			.isInstanceOf(CustomException.class)
			.satisfies(ex -> {
				CustomException ce = (CustomException) ex;
				assertThat(ce.getErrorCode()).isEqualTo(ErrorCode.INVALID_INPUT_VALUE);
			});


		BookStats stats1 = book.getBookStatsMap().get(1L);
		assertThat(stats1.getEmotionCount()).isEqualTo(0);

		assertThat(book.getTotalEmotionCount()).isEqualTo(0);
		assertThat(book.getTotalEmotionScoreSum()).isEqualTo(0);
	}
}