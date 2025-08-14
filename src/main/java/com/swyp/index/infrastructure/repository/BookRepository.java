package com.swyp.index.infrastructure.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.swyp.index.domain.book.Book;

public interface BookRepository extends JpaRepository<Book, Long> {

	Optional<Book> findByIsbn(String isbn);

	@Query("SELECT b.isbn FROM Book b WHERE b.isbn IN :isbns")
	List<String> findExistingIsbns(@Param("isbns") List<String> isbns);

	@Query("SELECT b FROM Book b LEFT JOIN FETCH b.bookStatsMap WHERE b.isbn = :isbn")
	Optional<Book> findByIsbnWithStats(String isbn);

	@Query("SELECT b FROM Book b LEFT JOIN FETCH b.bookStatsMap WHERE b.isbn IN :isbns")
	List<Book> findAllByIsbnInWithStats(List<String> isbns);

	@Query("SELECT COUNT(b) FROM Book b JOIN b.bookStatsMap bs " + "WHERE KEY(bs) = :emotionId AND bs.emotionScoreSum > 0")
	long countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero(@Param("emotionId") Long emotionId);

	// 감정으로 책을 조회, 해당 감정의 총 감정 점수 내림차순 정렬
	@Query("SELECT b FROM Book b JOIN b.bookStatsMap bs " + "WHERE KEY(bs) = :emotionId AND bs.emotionScoreSum > 0 "
		+ "ORDER BY bs.emotionScoreSum DESC, b.id ASC")
	List<Book> findBooksByEmotionIdOrderByEmotionScoreSumDescGreaterThanZero(@Param("emotionId") Long emotionId, Pageable pageable);
}
