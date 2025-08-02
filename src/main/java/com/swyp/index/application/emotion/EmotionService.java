package com.swyp.index.application.emotion;

import com.swyp.index.domain.emotion.EmotionType;
import com.swyp.index.presentation.dto.emotion.EmotionResponse;
import lombok.RequiredArgsConstructor;
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
}
