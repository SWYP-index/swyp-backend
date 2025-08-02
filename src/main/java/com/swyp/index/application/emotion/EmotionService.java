package com.swyp.index.application.emotion;

import com.swyp.index.domain.emotion.EmotionCategory;
import com.swyp.index.domain.emotion.EmotionType;
import com.swyp.index.presentation.dto.emotion.EmotionResponse;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class EmotionService {

    @Value("${cloud.aws.s3.base-url}")
    private String s3BaseUrl;


    public List<EmotionResponse> getAllEmotions() {
        // DB를 조회하지 않고, 코드에 정의된 EmotionType Enum의 모든 값을 DTO로 변환합니다.
        return Arrays.stream(EmotionType.values())
                .map(emotionType -> EmotionResponse.from(emotionType, s3BaseUrl))
                .collect(Collectors.toList());
    }

    public EmotionResponse getEmotionById(Long id, EmotionCategory category) {
        if (id == 0L) {
            // 카테고리별 기본 파일명 결정
            String fileName = switch (category) {
                case POSITIVE -> "positive_default.png";
                case NEGATIVE -> "negative_default.png";
                case NEUTRAL  -> "neutral_default.png";
                case THOUGHT  -> "thought_default.png";
            };
            return EmotionResponse.builder()
                    .id(0L)
                    .name("기본(" + category.getDisplayName() + ")")
                    .category(category.getDisplayName())
                    .iconImageUrl(s3BaseUrl + fileName)
                    .build();
        }

        // 일반 감정은 기존 enum → DTO 변환 사용
        EmotionType et = EmotionType.fromId(id);
        return EmotionResponse.from(et, s3BaseUrl);
    }
}
