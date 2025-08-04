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
@Schema(description = "독서 기록 (완독) 상세 조회 응답 DTO")
public class CompletionRecordResponse {

    @Schema(description = "기록 ID", example = "1")
    private final Long recordId;

    @Schema(description = "인상 깊은 구절 및 느낀 점", example = "주인공의 선택이 인상 깊었다.")
    private final String content;

    @Schema(description = "종합 감상평", example = "오랜만에 깊은 울림을 주는 책이었다.")
    private final String finalNote;

    @Schema(description = "완독 처리 시각", example = "2025-08-04T13:07:30")
    private final LocalDateTime finishedAt;

    @Schema(description = "기록에 연결된 감정 목록")
    private final List<EmotionResponse> emotions;

    @Builder
    private CompletionRecordResponse(Long recordId, String content, String finalNote, LocalDateTime finishedAt, List<EmotionResponse> emotions) {
        this.recordId = recordId;
        this.content = content;
        this.finalNote = finalNote;
        this.finishedAt = finishedAt;
        this.emotions = emotions;
    }

    public static CompletionRecordResponse from(PageRecord pr, Bookshelf bs) {
        return CompletionRecordResponse.builder()
                .recordId(pr.getId())
                .content(pr.getContent())
                .finalNote(bs.getFinalNote())
                .finishedAt(pr.getCreatedAt())
                .emotions(pr.getRecordEmotions().stream()
                        .map(CompletionRecordResponse.EmotionResponse::from)
                        .collect(Collectors.toList()))
                .build();
    }

    @Getter
    @Schema(description = "기록된 감정 정보")
    public static class EmotionResponse {

        @Schema(description = "감정 ID", example = "3")
        private final Long emotionId;

        @Schema(description = "감정 이름", example = "감동적인")
        private final String emotionName;

        @Schema(description = "감정 점수", example = "5")
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
