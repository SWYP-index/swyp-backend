package com.swyp.index.infrastructure.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.user.User;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;

public interface BookshelfRepository extends JpaRepository<Bookshelf, Long> {
    @Query("SELECT new com.swyp.index.presentation.dto.bookshelf.BookshelfBookDto(" + "b.id, b.bookInfo.title, b.bookInfo.author, b.bookInfo.coverImageUrl, bs.createdAt) " + "FROM Bookshelf bs JOIN bs.book b " + "WHERE bs.user.id = :userId AND bs.status = com.swyp.index.domain.bookshelf.ReadingStatus.FINISHED " + "AND bs.createdAt >= :sixMonthsAgo " + "ORDER BY bs.createdAt DESC")
    List<BookshelfResponse> findFinishedBooksByUserId(@Param("userId") Long userId, @Param("sixMonthsAgo") LocalDateTime sixMonthsAgo);

    // 유저와 책으로 책장 데이터가 존재하는지 확인
    boolean existsByUserAndBook(User user, Book book);

    // 유저와 책으로 책장 데이터 조회
    Optional<Bookshelf> findByUserAndBook(User user, Book book);


}