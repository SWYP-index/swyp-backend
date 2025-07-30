package com.swyp.index.presentation.dto.report;

import com.swyp.index.domain.emotion.EmotionType;


public record EmotionStatDto (
        EmotionType emotionType, //감정 종류
        int percentage //전체 감정 점수 대비 이 감정이 차지하는 비율(0~100)
) {}



