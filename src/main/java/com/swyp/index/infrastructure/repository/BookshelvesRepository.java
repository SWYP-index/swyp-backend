package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelves;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BookshelvesRepository extends JpaRepository<Bookshelves, Long> {
    //사용자와 책으로 bookshelf를 조회
    Optional<Bookshelves> findByUserAndBook(User user, Book book);

    //사용자와 책으로 Bookshelf 존재 여부를 확인
    boolean existsByUserAndBook(User user, Book book);

    //특정 사용자의 책들 중 지정된 독서 상태에 있는 책 목록 조회
    List<Bookshelves> findByUserAndStatus(User user, ReadingStatus status);


}
