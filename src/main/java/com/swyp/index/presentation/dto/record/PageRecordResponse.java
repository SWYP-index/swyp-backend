package com.swyp.index.presentation.dto.record;

import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public class PageRecordResponse {
    private final Long recordId;
    private final Integer page; // 페이지 기록이므로 page는 항상 존재 (Integer -> int)
    private final String content;
    private final LocalDateTime createdAt;
    private final List<EmotionResponse> emotions;

    @Builder
    private PageRecordResponse(Long recordId, int page, String content, LocalDateTime createdAt, List<EmotionResponse> emotions) {
        this.recordId = recordId;
        this.page = page;
        this.content = content;
        this.createdAt = createdAt;
        this.emotions = emotions;
    }

    public static PageRecordResponse from(PageRecord pr) {
        return PageRecordResponse.builder()
                .recordId(pr.getId())
                .page(pr.getPage())
                .content(pr.getContent())
                .createdAt(pr.getCreatedAt())
                .emotions(pr.getRecordEmotions().stream()
                        .map(PageRecordResponse.EmotionResponse::from)
                        .collect(Collectors.toList()))
                .build();
    }
    @Getter
    @Schema(description = "기록된 감정 정보")
    public static class EmotionResponse {
        private final Long emotionId;
        private final String emotionName;
        private final int score;

        @Builder
        private EmotionResponse(Long emotionId, String emotionName, int score) {
            this.emotionId = emotionId;
            this.emotionName = emotionName;
            this.score = score;
        }

        public static EmotionResponse from(RecordEmotion re) {
            return EmotionResponse.builder()
                    .emotionId(re.getEmotion().getId())
                    .emotionName(re.getEmotion().getName())
                    .score(re.getEmotionScore())
                    .build();
        }
    }
}
