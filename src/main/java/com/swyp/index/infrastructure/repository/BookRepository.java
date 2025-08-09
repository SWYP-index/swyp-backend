package com.swyp.index.infrastructure.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookStats;

public interface BookRepository extends JpaRepository<Book, Long> {

	List<Book> findAllByIsbnIn(List<String> isbns);

	@Query("SELECT b.isbn FROM Book b WHERE b.isbn IN :isbns")
	List<String> findExistingIsbns(@Param("isbns") List<String> isbns);

	// 기록하기 기능을 위해 새로 추가
	Optional<Book> findByIsbn(String isbn);

	@Query(
		"SELECT COUNT(b) FROM Book b JOIN b.bookStatsMap bs " + "WHERE KEY(bs) = :emotionId AND bs.emotionScoreSum > 0")
	long countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero(@Param("emotionId") Long emotionId);

	// 감정으로 책을 조회, 해당 감정의 총 감정 점수 내림차순 정렬
	@Query("SELECT b FROM Book b JOIN b.bookStatsMap bs " + "WHERE KEY(bs) = :emotionId AND bs.emotionScoreSum > 0 "
		+ "ORDER BY bs.emotionScoreSum DESC, b.id ASC")
	List<Book> findBooksByEmotionIdOrderByTotalEmotionScoreSumDescGreaterThanZero(@Param("emotionId") Long emotionId, Pageable pageable);

	// 책 ID로 감정 통계 리스트 조회, 감정 통계의 감정 점수 내림차순 정렬
	@Query("SELECT bs FROM Book b JOIN b.bookStatsMap bs WHERE b.id = :bookId ORDER BY bs.emotionScoreSum DESC, bs.id ASC")
	List<BookStats> findAllByBookIdOrderByEmotionScoreSumDesc(@Param("bookId") Long bookId);

	// 책 ID로 감정 통계 리스트 조회, 감정 통계의 감정 점수 내림차순 정렬(페이징)
	@Query("SELECT bs FROM Book b JOIN b.bookStatsMap bs WHERE b.id = :bookId AND bs.emotionScoreSum > 0 ORDER BY bs.emotionScoreSum DESC")
	List<BookStats> findTopByBookIdOrderByEmotionScoreSumDescGreaterThanZero(@Param("bookId") Long bookId, Pageable pageable);
}
