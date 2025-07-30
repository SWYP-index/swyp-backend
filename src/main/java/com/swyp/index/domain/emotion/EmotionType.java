package com.swyp.index.domain.emotion;

public enum EmotionType {

    // 긍정
    TOUCHING(EmotionGroup.POSITIVE), //감동
    EXCITED(EmotionGroup.POSITIVE), //설렘
    HOPE(EmotionGroup.POSITIVE), //희망
    EMPATHY(EmotionGroup.POSITIVE), //공감
    COMFORT(EmotionGroup.POSITIVE), //위로

    // 부정
    SADNESS(EmotionGroup.NEGATIVE), //슬픔
    ANGER(EmotionGroup.NEGATIVE), //분노
    CONFUSION(EmotionGroup.NEGATIVE), //혼란
    ANXIETY(EmotionGroup.NEGATIVE), //불안
    FRUSTRATION(EmotionGroup.NEGATIVE), //답답함

    // 중립
    SHOCK(EmotionGroup.NEUTRAL), //충격적임
    CALM(EmotionGroup.NEUTRAL), //차분함
    EMPTINESS(EmotionGroup.NEUTRAL), //공허함
    REGRET(EmotionGroup.NEUTRAL), //아쉬움
    PEACEFUL(EmotionGroup.NEUTRAL), //평온함

    // 사고 기반
    REALIZATION(EmotionGroup.COGNITIVE), //깨달음
    INSIGHT(EmotionGroup.COGNITIVE), //통찰
    QUESTION(EmotionGroup.COGNITIVE), //의문
    INSPIRATION(EmotionGroup.COGNITIVE), //영감
    REFLECTION(EmotionGroup.COGNITIVE); //반성

    private final EmotionGroup group;

    EmotionType(EmotionGroup group) {
        this.group = group;
    }

    public EmotionGroup getGroup() {
        return group;
    }

}
