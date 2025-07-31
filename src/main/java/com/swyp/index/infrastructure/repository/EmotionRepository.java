package com.swyp.index.infrastructure.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.swyp.index.domain.emotion.Emotion;

public interface EmotionRepository extends JpaRepository<Emotion, Long> {

	Optional<Emotion> findByName(String name);
}
