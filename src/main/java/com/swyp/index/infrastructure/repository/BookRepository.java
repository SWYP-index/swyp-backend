package com.swyp.index.infrastructure.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.swyp.index.domain.book.Book;

import io.lettuce.core.dynamic.annotation.Param;

public interface BookRepository extends JpaRepository<Book, Long> {

	List<Book> findAllByIsbnIn(List<String> isbns);

	@Query("SELECT b FROM Book b JOIN FETCH b.bookStats WHERE b.isbn IN :isbns")
	List<Book> findAllWithStats(@Param("isbns") List<String> isbns);

	@Query("SELECT b.isbn FROM Book b WHERE b.isbn IN :isbns")
	List<String> findExistingIsbns(@Param("isbns") List<String> isbns);
}
