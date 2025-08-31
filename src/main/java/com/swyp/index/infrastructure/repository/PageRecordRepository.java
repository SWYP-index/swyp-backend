package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface PageRecordRepository extends JpaRepository<PageRecord, Long> {
    //특정 기간 내의 모든 기록을, 연관된 감정정보까지 한 번에 조회

    @Query("SELECT pr FROM PageRecord pr " +
            "JOIN FETCH pr.recordEmotions re " +
            "JOIN FETCH re.emotion " +
            "WHERE pr.bookshelf.user = :user AND pr.createdAt BETWEEN :start AND :end")
    List<PageRecord> findRecordsWithEmotionByUserAndDate(@Param("user") User user, @Param("start")LocalDateTime start, @Param("end") LocalDateTime end);

    //특정 사용자의 특정 기간 동안의 모든 기록을 조회
    List<PageRecord> findAllByBookshelfUserAndCreatedAtBetween(User user, LocalDateTime start, LocalDateTime end);

    // 최신 기록 1개만 page 값으로 가져오기
    @Query("SELECT pr.page FROM PageRecord pr " +
           "WHERE pr.bookshelf.id = :bookshelfId " +
           "ORDER BY pr.createdAt DESC")
    List<Integer> findLatestPageByBookshelfId(@Param("bookshelfId") Long bookshelfId);

    @Query("SELECT COUNT(DISTINCT pr.bookshelf.user.id) FROM PageRecord pr WHERE pr.bookshelf.book.id = :bookId")
    long countDistinctUsersByBookId(@Param("bookId") Long bookId);
}
