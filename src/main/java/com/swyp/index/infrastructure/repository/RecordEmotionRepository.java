package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.bookshelf.RecordEmotion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RecordEmotionRepository extends JpaRepository<RecordEmotion, Long> {

    /**
     * 사용자 + 도서 기준 감정 점수 총합을 감정 타입별로 그룹화하여 가져오는 Projection
     */
    @Query("""
            SELECT e.emotion.emotion AS emotionType, SUM(e.emotionScore) AS totalScore
            FROM RecordEmotion e
            JOIN e.pageRecord pr
            JOIN pr.bookshelf bs
            JOIN bs.book b
            JOIN bs.user u          
            WHERE u.id = :userId AND b.isbn = :isbn
            GROUP BY e.emotion.emotion
            """)
    List<UserEmotionStatProjection> findBookEmotionStatsByIsbn(@Param("userId") Long userId, @Param("isbn") String isbn);


}
