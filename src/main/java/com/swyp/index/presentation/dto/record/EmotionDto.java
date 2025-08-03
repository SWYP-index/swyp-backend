package com.swyp.index.presentation.dto.record;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "감정 ID 및 점수 DTO")
public class EmotionDto {
    @NotNull(message = "감정 ID는 필수입니다.")
    @Schema(description = "감정의 고유 ID", example = "1")
    private Long emotionId;

    @Min(value = 1, message = "점수는 1 이상이어야 합니다.")
    @Max(value = 10, message = "점수는 10 이하이어야 합니다.")
    @Schema(description = "감정 점수 (1~10)", example = "8")
    private int score;
}