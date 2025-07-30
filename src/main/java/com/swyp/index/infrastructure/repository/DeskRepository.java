package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.bookshelf.Desk;
import com.swyp.index.presentation.dto.bookshelf.DeskBookDto;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DeskRepository extends JpaRepository<Desk, Long> {
    @Query("SELECT new com.swyp.index.presentation.dto.bookshelf.DeskBookDto(" +
            "b.id, b.title, b.author, b.coverImageUrl, d.createdAt, b.publisher, b.category, b.publishedDate) " +
            "FROM Desk d JOIN d.book b " +
            "WHERE d.user.id = :userId AND d.status = com.swyp.index.domain.bookshelf.ReadingStatus.READING " +
            "ORDER BY d.createdAt DESC")
    List<DeskBookDto> findReadingBooksByUserId(Long userId);
}
