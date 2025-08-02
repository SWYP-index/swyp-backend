package com.swyp.index.domain.emotion;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 감정 종류를 정의하는 엔티티
@Entity
@Getter
@NoArgsConstructor
public class Emotion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Enumerated(EnumType.STRING)
    private EmotionCategory category;

    @Column(nullable = false)
    private String iconImageUrl;

    public Emotion(String name, EmotionCategory category, String iconImageUrl) {
        this.name = name;
        this.category = category;
        this.iconImageUrl = iconImageUrl;
    }
}
