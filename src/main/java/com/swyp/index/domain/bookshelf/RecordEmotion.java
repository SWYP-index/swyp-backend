package com.swyp.index.domain.bookshelf;

import com.swyp.index.domain.emotion.Emotion;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 하나의 '기록 카드(PageRecord)'에 포함된 개별 감정과 점수를 나타내는 엔티티.
 */
@Entity
@Getter
@NoArgsConstructor
public class RecordEmotion {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 이 감정 기록이 속한 '기록 카드' */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "page_record_id")
    private PageRecord pageRecord;

    /** 어떤 종류의 감정인지 (감동, 기쁨 등) */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "emotion_id")
    private Emotion emotion;


    /** 해당 감정에 대한 점수 */
    private int emotionScore;

    @Builder
    public RecordEmotion(Emotion emotion, int emotionScore) {
        this.emotion = emotion;
        this.emotionScore = emotionScore;
    }

    // 연관관계 설정 pagerecord - recordemotion
    public void setPageRecord(PageRecord pageRecord) {
        this.pageRecord = pageRecord;
    }
}
