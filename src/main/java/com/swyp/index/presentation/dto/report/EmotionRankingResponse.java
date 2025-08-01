package com.swyp.index.presentation.dto.report;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "전체 감정 랭킹 응답 DTO")
public record EmotionRankingResponse(

        @Schema(description = "감정 ID", example = "1")
        Long emotionId,

        @Schema(description = "감정 이름", example = "감동")
        String emotionName,

        @Schema(description = "감정 점수 총합", example = "42")
        int score
) {}
