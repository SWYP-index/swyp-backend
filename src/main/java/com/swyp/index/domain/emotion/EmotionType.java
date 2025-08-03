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

	EXCITED(1L, "설렘", EmotionCategory.POSITIVE),
	MOVED(2L, "감동", EmotionCategory.POSITIVE),
	JOYFUL(3L, "유쾌한", EmotionCategory.POSITIVE),
	EMPATHETIC(4L, "공감", EmotionCategory.POSITIVE),
	COMFORTED(5L, "위로", EmotionCategory.POSITIVE),

	UNPLEASANT(6L, "불쾌한", EmotionCategory.NEGATIVE),
	SAD(7L, "슬픔", EmotionCategory.NEGATIVE),
	ANGRY(8L, "분노", EmotionCategory.NEGATIVE),
	CONFUSED(9L, "혼란", EmotionCategory.NEGATIVE),
	FEAR(10L, "공포", EmotionCategory.NEGATIVE),

	AWKWARD(11L, "어색한", EmotionCategory.NEUTRAL),
	SURPRISED(12L, "놀람", EmotionCategory.NEUTRAL),
	EMBARRASSED(13L, "당황한", EmotionCategory.NEUTRAL),
	FRUSTRATED(14L, "답답한", EmotionCategory.NEUTRAL),
	REGRET(15L, "아쉬움", EmotionCategory.NEUTRAL),

	INSIGHTFUL(16L, "통찰", EmotionCategory.THOUGHT),
	ENLIGHTENED(17L, "깨달음", EmotionCategory.THOUGHT),
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