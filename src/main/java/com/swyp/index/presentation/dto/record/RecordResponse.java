package com.swyp.index.presentation.dto.record;


import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@NoArgsConstructor

public class RecordResponse {
    private Long recordId;
    private int page;
    private String content;
    private LocalDateTime createdAt;
    private List<EmotionResponse> emotions;

    @Getter @NoArgsConstructor
    public static class EmotionResponse {
        private Long emotionId;
        private String emotionName;
        private int score;


        public static EmotionResponse of(RecordEmotion re) {
            EmotionResponse er = new EmotionResponse();
            er.emotionId   = re.getEmotion().getId();
            er.emotionName = re.getEmotion().getName();
            er.score       = re.getEmotionScore();
            return er;
        }
    }


    public static RecordResponse of(PageRecord pr) {
        RecordResponse dto = new RecordResponse();
        dto.recordId  = pr.getId();
        dto.page      = pr.getPage();
        dto.content   = pr.getContent();
        dto.createdAt = pr.getCreatedAt();
        dto.emotions  = pr.getRecordEmotions().stream()
                .map(EmotionResponse::of)
                .collect(Collectors.toList());
        return dto;
    }
}
