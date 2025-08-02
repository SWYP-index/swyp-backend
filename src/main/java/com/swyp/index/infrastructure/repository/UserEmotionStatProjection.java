package com.swyp.index.infrastructure.repository;


/**
 * 감정별 점수 총합 Projection
 */
public interface UserEmotionStatProjection {
    String getEmotionName(); // 감정 이름 (한글)
    Integer getTotalScore();  // 감정 점수 합계
}
