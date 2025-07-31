package com.swyp.index.presentation.dto.record;

import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Schema(description = "독서 기록 응답 DTO")
public class RecordResponse {

    @Schema(description = "기록 ID", example = "1")
    private final Long recordId;

    // ◀◀ [수정] int -> Integer, '다 읽음' 기록의 null 페이지를 허용하기 위함
    @Schema(description = "기록한 페이지 (완독 기록 시 null)", example = "106")
    private final Integer page;

    @Schema(description = "기록 내용", example = "주인공의 선택이 인상 깊었다.")
    private final String content;

    @Schema(description = "기록 생성일", example = "2025-07-31T02:48:41")
    private final LocalDateTime createdAt;

    @Schema(description = "기록에 포함된 감정 목록")
    private final List<EmotionResponse> emotions;

    @Builder
    private RecordResponse(Long recordId, Integer page, String content, LocalDateTime createdAt, List<EmotionResponse> emotions) {
        this.recordId = recordId;
        this.page = page;
        this.content = content;
        this.createdAt = createdAt;
        this.emotions = emotions;
    }

    public static RecordResponse from(PageRecord pr) {
        return RecordResponse.builder()
                .recordId(pr.getId())
                .page(pr.getPage())
                .content(pr.getContent())
                .createdAt(pr.getCreatedAt())
                .emotions(pr.getRecordEmotions().stream()
                        .map(EmotionResponse::from)
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