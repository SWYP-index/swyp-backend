package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.bookshelf.RecordEmotion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

/**
 * 감정 기록 조회용 Repository
 */
public interface RecordEmotionRepository extends JpaRepository<RecordEmotion, Long> {

    /**
     * 사용자 + 도서 기준 감정 점수 총합을 감정별로 집계
     *
     * @return 감정별 점수 총합 리스트
     * @Param userId 사용자 ID
     * @Param bookId 도서 ID
     */
    @Query("""
                SELECT e.emotion.name AS emotionName, SUM(e.emotionScore) AS totalScore
                FROM RecordEmotion e
                JOIN e.pageRecord pr
                JOIN pr.bookshelf bs
                JOIN bs.book b
                JOIN bs.user u
                WHERE u.id = :userId AND b.id  = :bookId
                GROUP BY e.emotion.name
            """)
    List<UserEmotionStatProjection> findBookEmotionStatsByBookId(
            @Param("userId") Long userId,
            @Param("bookId") Long bookId

    );


    // 사용자별 전체 기록에 대한 감정 점수 집계
    @Query("""
            SELECT e.emotion.name AS emotionName, SUM(e.emotionScore) AS totalScore
            FROM RecordEmotion e
            JOIN e.pageRecord pr
            JOIN pr.bookshelf bs
            JOIN bs.user u
            WHERE u.id = :userId
            GROUP BY e.emotion.name
            ORDER BY totalScore DESC                                                 
            """)

    List<UserEmotionStatProjection> findTopEmotionsByUserId(@Param("userId") Long userId);
}
