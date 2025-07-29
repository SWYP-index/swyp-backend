package com.swyp.index.domain.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.user.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

//사용자와 특정 책 사이의 관계를 나타내는 엔티티
//한 사용자가 한 책에 대해 가지는 독서 상태를 관리
@Entity
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor
public class Bookshelves {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "book_id", nullable = false)
    private Book book;

    @OneToMany(mappedBy = "bookshelves", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PageRecord> pageRecords = new ArrayList<>();


    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private ReadingStatus status;

    @CreatedDate @Column(updatable = false, nullable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    private LocalDateTime finishedAt;


    @Builder(access = AccessLevel.PRIVATE)
    private Bookshelves(User user, Book book, ReadingStatus status) {
        this.user = user;
        this.book = book;
        this.status = status;
    }

    //사용자가 책을 읽기 시작할 때 호출됨.
    public static Bookshelves startReading(User user, Book book) {
        return Bookshelves.builder()
                .user(user)
                .book(book)
                .status(ReadingStatus.READING)
                .build();
    }

    //페이지 기록을 추가
    public void addPageRecord(PageRecord pageRecord) {
        this.pageRecords.add(pageRecord);
        pageRecord.setBookshelves(this);
    }


    public void validateNotFinished() {
        if (this.status == ReadingStatus.FINISHED) {
            throw new IllegalStateException("이미 다 읽은 책에는 기록을 추가할 수 없습니다.");
        }
    }

    //독서를 완료 처리
    public void finish() {
        this.status = ReadingStatus.FINISHED;
        this.finishedAt = LocalDateTime.now();
    }


}
