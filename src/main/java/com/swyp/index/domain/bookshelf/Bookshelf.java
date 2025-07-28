package com.swyp.index.domain.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.user.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

//사용자와 특정 책 사이의 관계를 나타내는 엔티티
//한 사용자가 한 책에 대해 가지는 독서 상태를 관리
@Entity
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor
public class Bookshelf {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "book_id", nullable = false)
    private Book book;


    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private ReadingStatus status;

    @CreatedDate @Column(updatable = false, nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime finishedAt;


    @Builder(access = AccessLevel.PRIVATE)
    private Bookshelf(User user, Book book, ReadingStatus status) {
        this.user = user;
        this.book = book;
        this.status = status;
    }

    public static Bookshelf startReading(User user, Book book) {
        return Bookshelf.builder()
                .user(user)
                .book(book)
                .status(ReadingStatus.READING)
                .build();
    }

    /** 완독 후에는 기록 금지 */
    public void validateNotFinished() {
        if (this.status == ReadingStatus.FINISHED) {
            throw new IllegalStateException("이미 다 읽은 책에는 작업을 수행할 수 없습니다.");
        }
    }

    /** 완독 처리 */
    public void finish() {
        this.status = ReadingStatus.FINISHED;
        this.finishedAt = LocalDateTime.now();
    }


}
