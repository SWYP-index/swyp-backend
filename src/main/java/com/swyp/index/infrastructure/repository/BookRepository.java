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

    // @Query("SELECT b FROM Book b JOIN FETCH b.bookStats WHERE b.isbn IN :isbns")
    // List<Book> findAllWithStats(@Param("isbns") List<String> isbns);

    @Query("SELECT b.isbn FROM Book b WHERE b.isbn IN :isbns")
    List<String> findExistingIsbns(@Param("isbns") List<String> isbns);

    //기록하기 기능을 위해 새로 추가
    Optional<Book> findByIsbn(String isbn);

    // 책의 감정 통계에 따라 책을 정렬하여 페이지네이션
    // @Query(value = """
    //     SELECT b.*
    //     FROM book b
    //     JOIN book_stats_map bs ON bs.book_id = b.id
    //     WHERE bs.emotion_id = :emotionId
    //     ORDER BY bs.total_emotion_score DESC
    //     LIMIT :pageSize OFFSET :offset
    //     """, nativeQuery = true)
    // List<Book> findBooksByEmotionIdOrderByTotalEmotionScoreDesc(
    //     @Param("emotionId") Long emotionId,
    //     @Param("pageSize") int pageSize,
    //     @Param("offset") int offset
    // );

    @Query("SELECT b FROM Book b JOIN b.bookStatsMap bs WHERE KEY(bs) = :emotionId ORDER BY bs.totalEmotionScore DESC")
    List<Book> findBooksByEmotionIdOrderByTotalEmotionScoreDesc(@Param("emotionId") Long emotionId, Pageable pageable);

    @Query("SELECT bs FROM Book b JOIN b.bookStatsMap bs WHERE b.id = :bookId ORDER BY bs.totalEmotionScore DESC")
    List<BookStats> findTopByBookIdOrderByTotalEmotionScoreDesc(@Param("bookId") Long bookId, Pageable pageable);
}
