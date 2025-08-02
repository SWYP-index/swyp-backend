package com.swyp.index.presentation.dto.emotion;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.swyp.index.domain.emotion.EmotionType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@Schema(description = "감정 정보 응답 DTO")
public class EmotionResponse {

    @JsonProperty("emotionId")
    @Schema(description = "감정 고유 ID", example = "1")
    private final Long id;

    @Schema(description = "감정 이름", example = "감동")
    private final String name;

    @Schema(description = "감정 카테고리", example = "긍정")
    private final String category;

    @Schema(description = "아이콘 이미지 URL")
    private final String iconImageUrl;

    // EmotionType Enum을 DTO로 변환하는 정적 팩토리 메서드
    public static EmotionResponse from(EmotionType emotionType, String baseUrl) {
        return EmotionResponse.builder()
                .id(emotionType.getId())
                .name(emotionType.getName())
                .category(emotionType.getCategory().getDisplayName())
                .iconImageUrl(baseUrl + emotionType.getIconFileName())
                .build();
    }
}
