package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.user.User;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BookshelfRepository extends JpaRepository<Bookshelf, Long> {
    //사용자와 책으로 bookshelf를 조회
    Optional<Bookshelf> findByUserAndBook(User user, Book book);

    //사용자와 책으로 Bookshelf 존재 여부를 확인
    boolean existsByUserAndBook(User user, Book book);

    //특정 사용자의 책들 중 지정된 독서 상태에 있는 책 목록 조회
    List<Bookshelf> findByUserAndStatus(User user, ReadingStatus status);

    //특정 사용자가 최근 6개월 내에 완독한 책 목록을 조회
    @Query("SELECT new com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryResponse(" +
            "   b.id, b.title, b.author, b.coverImageUrl, bs.createdAt) " +
            "FROM Bookshelf bs JOIN bs.book b " +
            "WHERE bs.user.id = :userId AND bs.status = com.swyp.index.domain.bookshelf.ReadingStatus.FINISHED " +
            "AND bs.createdAt >= :sixMonthsAgo " +
            "ORDER BY bs.createdAt DESC")
    List<BookshelfSummaryResponse> findFinishedBooksByUserId(
            @Param("userId") Long userId,
            @Param("sixMonthsAgo") LocalDateTime sixMonthsAgo
    );



}
