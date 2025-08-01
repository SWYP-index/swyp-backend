package com.swyp.index.presentation.dto.report;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookInfo;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.presentation.dto.book.BookStatsDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;


/**
 * 사용자의 책 한 권에 대한 감정 분석 리포트 응답 DTO
 * - 독서 상태
 * - 도서 정보
 * - 감정 비율
 */
@Getter
@NoArgsConstructor
@Schema(description = "독서 리포트 카드 응답 DTO")
public class ReadingReportResponse {

    @Schema(description = "도서 제목")
    private String title;

    @Schema(description = "저자")
    private String author;

    @Schema(description = "ISBN")
    private String isbn;

    @Schema(description = "커버 이미지 URL")
    private String coverImageUrl;

    @Schema(description = "출판사")
    private String publisher;

    @Schema(description = "카테고리")
    private String category;

    @Schema(description = "발행일")
    private LocalDate pubDate;

    @Schema(description = "독서 상태")
    private String status;

    @Schema(description = "독서 시작일")
    private LocalDate createdAt;

    @Schema(description = "독서 완료일")
    private LocalDate finishedAt;

    @Schema(description = "현재 읽고 있는 페이지 (읽는 중일 경우)")
    private Integer currentPage;

    @Schema(description = "감정 비율 리스트")
    private List<BookStatsDto> emotionStats;

    /**
     * Bookshelf + 감정 분석 결과를 기반으로 응답 DTO 생성
     */
    public static ReadingReportResponse of(Bookshelf bookshelf, List<BookStatsDto> stats, Integer currentPage){
        Book book = bookshelf.getBook();
        BookInfo info = book.getBookInfo();

        ReadingReportResponse r = new ReadingReportResponse();

        r.title = info.getTitle();
        r.author = info.getAuthor();
        r.isbn = book.getIsbn();
        r.coverImageUrl = info.getCoverImageUrl();
        r.publisher = info.getPublisher();
        r.category = info.getCategory();
        r.pubDate = info.getPublishedDate();

        r.status = bookshelf.getStatus().name();
        r.createdAt = bookshelf.getCreatedAt().toLocalDate();
        r.finishedAt = bookshelf.getFinishedAt() != null ? bookshelf.getFinishedAt().toLocalDate() : null; // null 인지 체크

        r.currentPage = currentPage;
        r.emotionStats = stats;

        return r;
    }




}
