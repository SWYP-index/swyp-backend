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
@Schema(description = "페이지 단위 독서 기록 조회 응답 DTO")
public class PageRecordResponse {

    @Schema(description = "기록 ID", example = "15")
    private final Long recordId;

    @Schema(description = "기록된 페이지 번호", example = "88")
    private final Integer page;

    @Schema(description = "인상 깊은 구절 및 느낀 점", example = "이 부분에서 주인공의 심리가 잘 드러났다.")
    private final String content;

    @Schema(description = "기록 생성 시각", example = "2025-08-04T01:11:15")
    private final LocalDateTime createdAt;

    @Schema(description = "기록에 연결된 감정 목록")
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

        @Schema(description = "감정 ID", example = "5")
        private final Long emotionId;

        @Schema(description = "감정 이름", example = "흥미로운")
        private final String emotionName;

        @Schema(description = "감정 점수", example = "7")
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
