package com.swyp.index.domain.emotion;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

//감정 종류를 정의하는 엔티티
@Entity
@Getter
@NoArgsConstructor
public class Emotion {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EmotionType emotion;
}
