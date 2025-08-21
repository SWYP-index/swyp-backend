package com.swyp.index.domain.bookshelf;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

//사용자와 특정 책 사이의 관계를 나타내는 엔티티
//한 사용자가 한 책에 대해 가지는 독서 상태를 관리
@Entity
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor
public class Bookshelf {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "book_id", nullable = false)
    private Book book;

    @OneToMany(mappedBy = "bookshelf", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PageRecord> pageRecords = new ArrayList<>();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReadingStatus status;

    @CreatedDate
    @Column(updatable = false, nullable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    private LocalDateTime finishedAt;

    //종합 감상평을 위한 필드 추가
    @Lob
    private String finalNote;


    @Builder(access = AccessLevel.PRIVATE)
    private Bookshelf(User user, Book book, ReadingStatus status) {
        this.user = user;
        this.book = book;
        this.status = status;
    }

    //사용자가 책을 읽기 시작할 때 호출됨.
    public static Bookshelf startReading(User user, Book book) {
        return Bookshelf.builder().user(user).book(book).status(ReadingStatus.READING).build();
    }

    public static Bookshelf finishReading(User user, Book book){
        return Bookshelf.builder().user(user).book(book).status(ReadingStatus.FINISHED).build();
    }

    //페이지 기록을 추가
    public void addPageRecord(PageRecord pageRecord) {
        this.pageRecords.add(pageRecord);
        pageRecord.setBookshelf(this);
    }

    /**
     * 페이지 기록을 제거하고 연관관계를 끊습니다.
     */
    public void removePageRecord(PageRecord pageRecord) {
        this.pageRecords.remove(pageRecord);
        pageRecord.setBookshelf(null);
    }

    /**
     * 최종 감상평(finalNote)만 수정하는 메서드
     */
    public void updateFinalNote(String finalNote) {
        this.finalNote = finalNote;
    }

    /**
     * 완독 상태를 취소하고 '읽는 중' 상태로 되돌립니다.
     */
    public void cancelFinish() {
        this.status = ReadingStatus.READING;
        this.finishedAt = null;
        this.finalNote = null;
    }



    //독서를 완료 처리
    public void finish(String finalNote) {
        this.status = ReadingStatus.FINISHED;
        this.finishedAt = LocalDateTime.now();
        this.finalNote = finalNote;
    }

    public void updateStatus(String status) {
        try {
            this.status = ReadingStatus.valueOf(status.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new CustomException(ErrorCode.INVALID_READING_STATUS);
        }
    }
}
