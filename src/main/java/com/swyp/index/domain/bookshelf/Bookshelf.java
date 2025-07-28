package com.swyp.index.domain.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.user.User;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;

//사용자와 특정 책 사이의 관계를 나타내는 엔티티
//한 사용자가 한 책에 대해 가지는 독서 상태를 관리
@Entity
@Getter
@NoArgsConstructor
public class Bookshelf {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 이 책장을 소유한 사용자 */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** 책장에 꽂혀 있는 책 */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "book_id", nullable = false)
    private Book book;

    /** 현재 독서 상태 (WISH, READING, FINISHED) */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReadingStatus status;

    @CreatedDate
    @Column(updatable = false, nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime finishedAt;

    @Builder
    public Bookshelf(User user, Book book, ReadingStatus status){
        this.user = user;
        this.book = book;
        this.status = status;
    }

    /** 책의 상태를 '다 읽음'으로 변경하고, 완독 날짜를 기록*/
    public void finishBook(){
        this.status = ReadingStatus.FINISHED;
        this.finishedAt = LocalDateTime.now();
    }

    /** 독서 상태를 변경하는 메서드*/
    public void updateStatus(ReadingStatus newStatus) {
        this.status = newStatus;
    }
}
