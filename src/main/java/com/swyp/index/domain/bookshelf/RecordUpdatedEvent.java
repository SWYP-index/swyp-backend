package com.swyp.index.domain.bookshelf;

import java.util.List;
import java.util.stream.Collectors;

public record RecordUpdatedEvent(
        Long bookId, List<RecordEmotionInfo> oldEmotions, List<RecordEmotionInfo> newEmotions
) {
    public static RecordUpdatedEvent of(Long bookId, List<RecordEmotion> oldEmotions, List<RecordEmotion> newEmotions){
        List<RecordEmotionInfo> oldInfos = oldEmotions.stream().map(RecordEmotionInfo::from).collect(Collectors.toList());
        List<RecordEmotionInfo> newInfos = newEmotions.stream().map(RecordEmotionInfo::from).collect(Collectors.toList());
        return new RecordUpdatedEvent(bookId, oldInfos, newInfos);
    }

    public record RecordEmotionInfo(Long emotionId, int score){
        public static RecordEmotionInfo from(RecordEmotion re){
            return new RecordEmotionInfo(re.getEmotion().getId(), re.getEmotionScore());
        }
    }
}
