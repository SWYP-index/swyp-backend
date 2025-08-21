package com.swyp.index.presentation.dto.record;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
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
@Builder
@Schema(description = "통합 기록 조회 응답 DTO (페이지/완독 기록 겸용)")
public class UnifiedRecordResponse {

    @Schema(description = "기록의 고유 ID", example = "101")
    private final Long recordId;

    @Schema(description = "기록의 상태 (READING: 페이지 기록, FINISHED: 완독 기록)", example = "READING")
    private final ReadingStatus status;

    @Schema(description = "기록 생성 또는 완독 시각", example = "2025-08-17 14:08:30")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final LocalDateTime createdAt;

    @Schema(description = "기록된 페이지 번호 (완독 기록의 경우 null)", example = "88")
    private final Integer page;

    @Schema(description = "기록 내용 (페이지 기록) 또는 인상 깊은 구절 (완독 기록)", example = "주인공의 선택이 인상 깊었다.")
    private final String content;

    @Schema(description = "종합 감상평 (status가 FINISHED인 완독 기록에만 존재)", example = "오랜만에 깊은 울림을 주는 책이었다.")
    private final String finalNote;

    @Schema(description = "기록에 연결된 감정 목록")
    private final List<EmotionResponse> emotions;

    /**
     * PageRecord를 '페이지 기록' DTO로 변환합니다. 상태는 READING으로 설정됩니다.
     */
    public static UnifiedRecordResponse fromPageRecord(PageRecord pageRecord) {
        return UnifiedRecordResponse.builder()
                .recordId(pageRecord.getId())
                .status(ReadingStatus.READING)
                .createdAt(pageRecord.getCreatedAt())
                .page(pageRecord.getPage())
                .content(pageRecord.getContent())
                .emotions(pageRecord.getRecordEmotions().stream()
                        .map(EmotionResponse::from)
                        .collect(Collectors.toList()))
                .build();
    }

    /**
     * 완독 시점의 PageRecord와 Bookshelf를 '완독 기록' DTO로 변환합니다. 상태는 FINISHED로 설정됩니다.
     */
    public static UnifiedRecordResponse fromCompletionRecord(PageRecord pageRecord, Bookshelf bookshelf) {
        return UnifiedRecordResponse.builder()
                .recordId(pageRecord.getId())
                .status(ReadingStatus.FINISHED)
                .createdAt(pageRecord.getCreatedAt())
                .page(pageRecord.getPage()) // 완독 기록은 page가 null
                .content(pageRecord.getContent())
                .finalNote(bookshelf.getFinalNote())
                .emotions(pageRecord.getRecordEmotions().stream()
                        .map(EmotionResponse::from)
                        .collect(Collectors.toList()))
                .build();
    }

    // 기존 DTO들과의 호환성을 위해 EmotionResponse 중첩 클래스를 그대로 사용합니다.
    @Getter
    @Schema(description = "기록된 감정 정보")
    public static class EmotionResponse {
        @Schema(description = "감정의 고유 ID", example = "3")
        private final Long emotionId;
        @Schema(description = "감정 이름", example = "감동적인")
        private final String emotionName;
        @Schema(description = "감정 점수 (1~10)", example = "9")
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