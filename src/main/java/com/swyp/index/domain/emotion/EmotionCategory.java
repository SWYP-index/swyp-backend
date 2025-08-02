package com.swyp.index.domain.emotion;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum EmotionCategory {
	POSITIVE("긍정"),
	NEGATIVE("부정"),
	NEUTRAL("중립"),
	THOUGHT("사고기반");

	private final String displayName;
}