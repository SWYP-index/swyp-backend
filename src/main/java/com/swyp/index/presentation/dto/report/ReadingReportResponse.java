package com.swyp.index.presentation.dto.report;


import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.presentation.dto.book.BookInfoDto;
import com.swyp.index.presentation.dto.book.BookStatsDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
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

    @Schema(description = "책장 고유 ID", example = "101")
    private Long bookshelfId;

    @Schema(description = "독서 상태(Reading, Finished)", example = "READING")
    private String status;

    @Schema(description = "독서 시작일", example = "2025-07-01T00:00:00")
    private LocalDateTime createdAt;

    @Schema(description = "독서 완료일", example = "2025-07-20T00:00:00")
    private LocalDateTime finishedAt;

    @Schema(description = "도서 정보")
    private BookInfoDto book;

    @Schema(description = "감정 비율 리스트")
    private List<BookStatsDto> emotionStats;

    /**
     * Bookshelf + 감정 분석 결과를 기반으로 응답 DTO 생성
     */
    public static ReadingReportResponse of(Bookshelf bookshelf, List<BookStatsDto> stats){
        ReadingReportResponse r = new ReadingReportResponse();
        r.bookshelfId = bookshelf.getId();
        r.status = bookshelf.getStatus().name();
        r.createdAt = bookshelf.getCreatedAt();
        r.finishedAt = bookshelf.getFinishedAt();
        r.book = BookInfoDto.from(bookshelf.getBook());
        r.emotionStats = stats;
        return r;
    }




}
