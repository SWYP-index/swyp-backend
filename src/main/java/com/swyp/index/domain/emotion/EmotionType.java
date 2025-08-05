package com.swyp.index.domain.emotion;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum EmotionType {

	// POSITIVE (1-5)
	MOVED(1L, "감동", EmotionCategory.POSITIVE),     // 원래 2번이었음
	EXCITED(2L, "설렘", EmotionCategory.POSITIVE),   // 원래 1번이었음
	JOYFUL(3L, "유쾌한", EmotionCategory.POSITIVE),
	EMPATHETIC(4L, "공감", EmotionCategory.POSITIVE),
	COMFORTED(5L, "위로", EmotionCategory.POSITIVE),

	// NEGATIVE (6-10)
	SAD(6L, "슬픔", EmotionCategory.NEGATIVE),
	ANGRY(7L, "분노", EmotionCategory.NEGATIVE),
	CONFUSED(8L, "혼란", EmotionCategory.NEGATIVE),
	UNPLEASANT(9L, "불쾌한", EmotionCategory.NEGATIVE), // ID 순서에 맞게 조정
	FEAR(10L, "공포", EmotionCategory.NEGATIVE),

	// NEUTRAL (11-15)
	SURPRISED(11L, "놀람", EmotionCategory.NEUTRAL),
	EMBARRASSED(12L, "당황한", EmotionCategory.NEUTRAL),
	FRUSTRATED(13L, "답답한", EmotionCategory.NEUTRAL),
	REGRET(14L, "아쉬운", EmotionCategory.NEUTRAL),
	AWKWARD(15L, "어색한", EmotionCategory.NEUTRAL),

	// THOUGHT (16-20)
	ENLIGHTENED(16L, "깨달음", EmotionCategory.THOUGHT),
	INSIGHTFUL(17L, "통찰", EmotionCategory.THOUGHT),
	QUESTION(18L, "의문", EmotionCategory.THOUGHT),
	INSPIRED(19L, "영감", EmotionCategory.THOUGHT),
	REFLECTION(20L, "성찰", EmotionCategory.THOUGHT);


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
			throw new CustomException(ErrorCode.EMOTION_NOT_FOUND);
		}

		return type.getName();
	}

	public static Long getIdByName(String name) {
		EmotionType type = NAME_MAP.get(name);

		if (type == null) {
			throw new CustomException(ErrorCode.EMOTION_NOT_FOUND);
		}

		return type.getId();
	}

	public static EmotionType fromName(String name) {
		return Arrays.stream(values())
				.filter(e -> e.name.equals(name)) // 이름이 정확히 일치할 경우만
				.findFirst()
				.orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
	}
}