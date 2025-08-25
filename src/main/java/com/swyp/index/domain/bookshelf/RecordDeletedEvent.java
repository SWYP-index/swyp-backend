package com.swyp.index.domain.bookshelf;

import java.util.List;
import java.util.stream.Collectors;

public record RecordDeletedEvent(Long bookId, List<RecordDeletedEventEmotion> emotions) {

    public static RecordDeletedEvent from(Long bookId, List<RecordEmotion> RecordEmotions){
        List<RecordDeletedEventEmotion> emotions = RecordEmotions.stream()
                .map(e-> new RecordDeletedEventEmotion(e.getEmotion().getId(), e.getEmotionScore()))
                .collect(Collectors.toList());
        return new RecordDeletedEvent(bookId, emotions);
    }

    public record RecordDeletedEventEmotion(Long emotionId, int score) {
    }
}
