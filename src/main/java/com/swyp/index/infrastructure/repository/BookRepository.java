package com.swyp.index.infrastructure.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.swyp.index.domain.book.Book;
import org.springframework.data.repository.query.Param;


public interface BookRepository extends JpaRepository<Book, Long> {

    List<Book> findAllByIsbnIn(List<String> isbns);

    @Query("SELECT b FROM Book b JOIN FETCH b.bookStats WHERE b.isbn IN :isbns")
    List<Book> findAllWithStats(@Param("isbns") List<String> isbns);

    @Query("SELECT b.isbn FROM Book b WHERE b.isbn IN :isbns")
    List<String> findExistingIsbns(@Param("isbns") List<String> isbns);

    //기록하기 기능을 위해 새로 추가
    Optional<Book> findByIsbn(String isbn);
}
