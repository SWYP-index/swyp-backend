package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.presentation.dto.bookshelf.BookshelfBookDto;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface BookshelfRepository extends JpaRepository<Bookshelf, Long> {
    @Query("SELECT new com.swyp.index.presentation.dto.bookshelf.BookshelfBookDto(" +
            "b.id, b.title, b.author, b.coverImageUrl, bs.createdAt, b.publisher, b.category, b.publishedDate) " +
            "FROM Bookshelf bs JOIN bs.book b " +
            "WHERE bs.user.id = :userId AND bs.status = com.swyp.index.domain.bookshelf.ReadingStatus.FINISHED " +
            "AND bs.createdAt >= :sixMonthsAgo " +
            "ORDER BY bs.createdAt DESC")
    List<BookshelfBookDto> findFinishedBooksByUserId(
            @Param("userId") Long userId,
            @Param("sixMonthsAgo") LocalDateTime sixMonthsAgo
    );

}