package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.emotion.Emotion;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmotionRepository extends JpaRepository<Emotion, Long> {
}
