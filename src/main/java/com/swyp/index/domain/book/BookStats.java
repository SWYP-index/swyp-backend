package com.swyp.index.domain.book;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EntityListeners(AuditingEntityListener.class)
@Table(
	indexes = {
		@Index(name = "idx_emotion_id_score_sum", columnList = "emotion_id, emotion_score_sum"),
		@Index(name = "idx_book_id_score_sum", columnList = "book_id, emotion_score_sum")
	}
)
public class BookStats {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Setter
	private Long emotionId;

	private Long emotionCount = 0L;

	private Long emotionScoreSum = 0L;

	private Double emotionScoreAverage = 0.0;

	@CreatedDate
	@Column(updatable = false)
	private LocalDateTime createdAt;

	@LastModifiedDate
	private LocalDateTime updatedAt;

	public void record(int score) {
		this.emotionCount += 1;
		this.emotionScoreSum += score;
		this.emotionScoreAverage = (double) this.emotionScoreSum / this.emotionCount;
	}
}
