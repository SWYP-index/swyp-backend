package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.emotion.EmotionType;

public interface UserEmotionStatProjection {
    EmotionType getEmotionType();
    Integer getTotalScore();
}
