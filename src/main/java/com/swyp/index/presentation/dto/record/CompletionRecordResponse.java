package com.swyp.index.presentation.dto.record;

import com.swyp.index.domain.bookshelf.Bookshelf;
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
public class CompletionRecordResponse {
    private final Long recordId;
    private final String content;
    private final String finalNote;

    //  createdAt 필드 이름을 finishedAt으로 변경하여 의미를 명확화
    @Schema(description = "완독 처리 시각")
    private final LocalDateTime finishedAt;
    private final ReadingStatus status;

    private final List<EmotionResponse> emotions;

    @Builder
    private CompletionRecordResponse(Long recordId, String content, String finalNote, LocalDateTime finishedAt, ReadingStatus status, List<EmotionResponse> emotions) {
        this.recordId = recordId;
        this.content = content;
        this.finalNote = finalNote;
        this.finishedAt = finishedAt;
        this.status = status;
        this.emotions = emotions;
    }

    public static CompletionRecordResponse from(PageRecord pr, Bookshelf bs) {
        return CompletionRecordResponse.builder()
                .recordId(pr.getId())
                .content(pr.getContent())
                .finalNote(bs.getFinalNote())
                //  PageRecord의 생성 시각(createdAt)을 finishedAt 필드에 매핑
                .finishedAt(pr.getCreatedAt())
                .status(ReadingStatus.FINISHED)
                .emotions(pr.getRecordEmotions().stream()
                        .map(CompletionRecordResponse.EmotionResponse::from)
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