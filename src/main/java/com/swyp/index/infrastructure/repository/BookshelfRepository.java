package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.user.User;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BookshelfRepository extends JpaRepository<Bookshelf, Long> {
    @Query("SELECT DISTINCT bs FROM Bookshelf bs JOIN FETCH bs.book b " +
            "LEFT JOIN FETCH bs.pageRecords pr " +
            "WHERE bs.user.id = :userId AND bs.status = com.swyp.index.domain.bookshelf.ReadingStatus.FINISHED " +
            "AND bs.createdAt >= :sixMonthsAgo " +
            "ORDER BY bs.createdAt DESC")
    List<Bookshelf> findFinishedBooksByUserId(@Param("userId") Long userId, @Param("sixMonthsAgo") LocalDateTime sixMonthsAgo);

    // 유저와 책으로 책장 데이터가 존재하는지 확인
    boolean existsByUserAndBook(User user, Book book);

    // 유저와 책으로 책장 데이터 조회
    Optional<Bookshelf> findByUserAndBook(User user, Book book);

    //특정 기간 내에 독서를 시작한 책장 목록 조회
    List<Bookshelf> findAllByUserAndCreatedAtBetween(User user, LocalDateTime start, LocalDateTime end);

    //특정 기간 내에 독서를 완료한 책장 목록 조회
    List<Bookshelf> findAllByUserAndFinishedAtBetween(User user, LocalDateTime start, LocalDateTime end);

    //읽는 중인 책 목록을 책 정보와 함께 조회(책상 기능의 핵심)
    @Query("SELECT DISTINCT bs FROM Bookshelf bs JOIN FETCH bs.book b " +
            "LEFT JOIN FETCH bs.pageRecords pr " +
            "WHERE bs.user.id = :userId AND bs.status = com.swyp.index.domain.bookshelf.ReadingStatus.READING " +
            "ORDER BY bs.updatedAt DESC")
    List<Bookshelf> findReadingBooksByUserId(@Param("userId") Long userId);

    //  1단계: Bookshelf와 PageRecord만 가져오는 쿼리
    @Query("SELECT DISTINCT bs FROM Bookshelf bs " +
            "LEFT JOIN FETCH bs.pageRecords pr " +
            "WHERE bs.id = :bookshelfId")
    Optional<Bookshelf> findByIdWithPageRecords(@Param("bookshelfId") Long bookshelfId);

    //  2단계: PageRecord에 속한 RecordEmotion을 가져오는 쿼리
    @Query("SELECT DISTINCT pr FROM PageRecord pr " +
            "LEFT JOIN FETCH pr.recordEmotions re " +
            "LEFT JOIN FETCH re.emotion " +
            "WHERE pr IN :pageRecords")
    List<PageRecord> findPageRecordsWithEmotions(@Param("pageRecords") List<PageRecord> pageRecords);

}