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

	// 긍정
	MOVED(1L, "감동", EmotionCategory.POSITIVE,"positive_gamdong.png"),
	EXCITED(2L, "설렘", EmotionCategory.POSITIVE, "positive_sullem.png"),
	JOYFUL(3L, "유쾌한", EmotionCategory.POSITIVE, "positive_yuque.png"),
	EMPATHETIC(4L, "공감", EmotionCategory.POSITIVE,"positive_gonggam.png"),
	COMFORTED(5L, "위로", EmotionCategory.POSITIVE,"positive_wiro.png"),

	// 부정
	SAD(6L, "슬픔", EmotionCategory.NEGATIVE, "negative_seulpeum.png"),
	ANGRY(7L, "분노", EmotionCategory.NEGATIVE,"negative_bunno.png"),
	CONFUSED(8L, "혼란", EmotionCategory.NEGATIVE,"negative_honlan.png"),
	UNPLEASANT(9L, "불쾌한", EmotionCategory.NEGATIVE,"negative_bulquehan.png"),
	AFRAID(10L, "공포", EmotionCategory.NEGATIVE,"negative_gongpo.png"),

	// 중립
	SURPRISED(11L, "놀람", EmotionCategory.NEUTRAL, "neutral_nollam.png"),
	FLUSTERED(12L, "당황한", EmotionCategory.NEUTRAL,"neutral_danghwanghan.png"),
	FRUSTRATED(13L, "답답한", EmotionCategory.NEUTRAL,"neutral_dapdaphan.png"),
	REGRETFUL(14L, "아쉬운", EmotionCategory.NEUTRAL,"neutral_aswium.png"),
	AWKWARD(15L, "어색한", EmotionCategory.NEUTRAL,"neutral_eosaekhan.png"),

	// 사고 기반
	ENLIGHTENED(16L, "깨달음", EmotionCategory.THOUGHT,"thought_ggaedareum.png"),
	INSIGHTFUL(17L, "통찰", EmotionCategory.THOUGHT,"thought_tongchal.png"),
	CURIOUS(18L, "의문", EmotionCategory.THOUGHT,"thought_uimun.png"),
	INSPIRED(19L, "영감", EmotionCategory.THOUGHT,"thought_yeonggam.png"),
	INTROSPECTIVE(20L, "성찰", EmotionCategory.THOUGHT,"thought_seongchal.png");

	private final Long id;
	private final String name;
	private final EmotionCategory category;
	private final String iconFileName;

	private static final Map<Long, EmotionType> ID_MAP = new HashMap<>();
	private static final Map<String, EmotionType> NAME_MAP = new HashMap<>();

	static {
		for (EmotionType type : EmotionType.values()) {
			ID_MAP.put(type.id, type);
			NAME_MAP.put(type.name, type);
		}
	}

	//ID로 Enum 전체를 찾는 성능이 최적화된 메서드 추가
	public static EmotionType fromId(Long id) {
		EmotionType type = ID_MAP.get(id);
		if (type == null) {
			throw new IllegalArgumentException("Invalid emotion ID: " + id);
		}
		return type;
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

	public static EmotionType fromName(String name) {
		return Arrays.stream(values())
				.filter(e -> e.name.equals(name)) // 이름이 정확히 일치할 경우만
				.findFirst()
				.orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
	}
}