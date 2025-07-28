package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface BookshelfRepository extends JpaRepository<Bookshelf, Long> {
    //사용자와 책으로 bookshelf를 조회
    Optional<Bookshelf> findByUserAndBook(User user, Book book);
}
