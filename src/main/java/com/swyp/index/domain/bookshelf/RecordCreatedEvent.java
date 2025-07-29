package com.swyp.index.domain.bookshelf;

import java.util.List;
import java.util.stream.Collectors;


public record RecordCreatedEvent(Long bookId, List<RecordCreatedEventEmotion> emotions) {

	public static RecordCreatedEvent from(Long bookId, List<RecordEmotion> RecordEmotions) {
		List<RecordCreatedEventEmotion> emotions = RecordEmotions.stream()
			.map(e -> new RecordCreatedEventEmotion(e.getEmotion().getId(), e.getEmotionScore()))
			.collect(Collectors.toList());

		return new RecordCreatedEvent(bookId, emotions);
	}

	public record RecordCreatedEventEmotion(Long emotionId, int score) {
	}
}