package com.swyp.index.domain.emotion;

import java.util.HashMap;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum EmotionType {

	// 긍정
	MOVED(1L, "감동", EmotionCategory.POSITIVE),
	EXCITED(2L, "설렘", EmotionCategory.POSITIVE),
	HOPEFUL(3L, "희망", EmotionCategory.POSITIVE),
	EMPATHETIC(4L, "공감", EmotionCategory.POSITIVE),
	COMFORTED(5L, "위로", EmotionCategory.POSITIVE),

	// 부정
	SAD(6L, "슬픔", EmotionCategory.NEGATIVE),
	ANGRY(7L, "분노", EmotionCategory.NEGATIVE),
	CONFUSED(8L, "혼란", EmotionCategory.NEGATIVE),
	ANXIOUS(9L, "불안", EmotionCategory.NEGATIVE),
	FRUSTRATED(10L, "답답함", EmotionCategory.NEGATIVE),

	// 중립
	CALM(11L, "차분함", EmotionCategory.NEUTRAL),
	EMPTY(12L, "공허한", EmotionCategory.NEUTRAL),
	REGRET(13L, "아쉬움", EmotionCategory.NEUTRAL),
	PEACEFUL(14L, "평온함", EmotionCategory.NEUTRAL),
	SHOCKED(15L, "충격적인", EmotionCategory.NEUTRAL),

	// 사고 기반
	ENLIGHTENED(16L, "깨달음", EmotionCategory.THOUGHT),
	INSIGHTFUL(17L, "통찰", EmotionCategory.THOUGHT),
	CURIOUS(18L, "의문", EmotionCategory.THOUGHT),
	INSPIRED(19L, "영감", EmotionCategory.THOUGHT),
	REFLECTIVE(20L, "반성", EmotionCategory.THOUGHT);

	private final Long id;
	private final String name;
	private final EmotionCategory category;

	private static final Map<Long, EmotionType> ID_MAP = new HashMap<>();
	private static final Map<String, EmotionType> NAME_MAP = new HashMap<>();

	static {
		for (EmotionType type : EmotionType.values()) {
			ID_MAP.put(type.id, type);
			NAME_MAP.put(type.name, type);
		}
	}

	public static String getNameById(Long id) {
		EmotionType type = ID_MAP.get(id);
		if (type == null) {
			throw new IllegalArgumentException("Invalid emotion ID: " + id);
		}

		return type.getName();
	}

	public static Long getIdByName(String name) {
		EmotionType type = NAME_MAP.get(name);
		if (type == null) {
			throw new IllegalArgumentException("Invalid emotion name: " + name);
		}

		return type.getId();
	}
}