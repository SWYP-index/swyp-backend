package com.swyp.index.domain.bookshelf;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
// 사용자의 특정 페이지에 대해 남기는 기록 엔티티
@Entity
@Getter
@NoArgsConstructor
@EntityListeners(AuditingEntityListener.class) // 생성일 자동 기록을 위해 추가
public class PageRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 이 기록이 속한 책장(사용자와 책의 관계) */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "bookshelf_id", nullable = false)
    private Bookshelf bookshelf;

    /** 기록을 남긴 페이지 */
    private int page;

    /** 기록 내용 */
    @Lob // 긴 텍스트를 저장
    private String content;

    /** 기록 생성일 */
    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createdAt;

    /** 이 기록에 포함된 감정/점수 목록 */
    @OneToMany(mappedBy = "pageRecord", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RecordEmotion> recordEmotions = new ArrayList<>();

    @Builder(access = AccessLevel.PRIVATE)
    public PageRecord(Bookshelf bookshelf, int page, String content) {
        this.bookshelf = bookshelf;
        this.page = page;
        this.content = content;
    }

    // 페이지 기록과 감정 목록을 한 번에 생성
    public static PageRecord create(
            Bookshelf bookshelf,
            int page,
            String content,
            List<RecordEmotion> recordEmotions
    ) {
        //완독된 책장에는 기록 불가
        bookshelf.validateNotFinished();

        //기록 인스턴스 생성
        PageRecord pr = PageRecord.builder()
                .bookshelf(bookshelf)
                .page(page)
                .content(content)
                .build();

        //감정 연관관계 연결
        pr.addRecordEmotions(recordEmotions);

        return pr;
    }
    //Bookshelf와 양방향 연관관계 설정용 메서드
    public void setBookshelf(Bookshelf bookshelf) {
        this.bookshelf = bookshelf;
    }

    //연관된 감정 엔티티 연결
    public void addRecordEmotions(List<RecordEmotion> recordEmotions) {
        this.recordEmotions.addAll(recordEmotions);
        recordEmotions.forEach(e -> e.setPageRecord(this));
    }
}


