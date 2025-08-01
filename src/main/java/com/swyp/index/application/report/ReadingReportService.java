package com.swyp.index.application.report;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.PageRecordRepository;
import com.swyp.index.presentation.dto.book.BookStatsDto;
import com.swyp.index.presentation.dto.report.ReadingReportResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 사용자의 READING/FINISHED 책에 대해
 * 감정 분석 결과를 포함한 리포트 응답 생성
 */
@Service
@RequiredArgsConstructor
public class ReadingReportService {

    private final BookshelfRepository bookshelfRepository;
    private final EmotionAnalysisService emotionAnalysisService;
    private final PageRecordRepository pageRecordRepository;

    /**
     * 사용자의 모든 책장(읽는 중 + 완독) 목록에 대해 감정 통계를 포함한 리포트 생성
     */
    public List<ReadingReportResponse> getUserReadingReport(Long userId) {
        // 1. 읽는 중인 책 (책상)
        List<Bookshelf> readingBooks = bookshelfRepository.findReadingBooksByUserId(userId);

        // 2. 완독한 책 (책장)
        List<Bookshelf> finishedBooks = bookshelfRepository.findFinishedBooksByUserId(userId, LocalDateTime.now().minusMonths(6));

        // 3. 병합
        List<Bookshelf> allBooks = Stream.concat(readingBooks.stream(), finishedBooks.stream())
                .sorted(Comparator.comparing(Bookshelf::getUpdatedAt).reversed()) // 최신순 정렬
                .toList();

        // 4. 감정 통계 포함한 응답 DTO로 변환
        return allBooks.stream()
                .map(bs -> {
                    String isbn = bs.getBook().getIsbn();
                    List<BookStatsDto> stats = emotionAnalysisService.getUserBookEmotionStats(userId, isbn);

                    //current page 계산(Reading 상태일 때만)
                    Integer currentPage = null;
                    if(bs.getStatus() == ReadingStatus.READING){
                        currentPage = pageRecordRepository
                                .findLatestPageByBookshelfId(bs.getId())
                                .stream()
                                .findFirst()
                                .orElse(null);
                    }
                    return ReadingReportResponse.of(bs, stats, currentPage);
                })
                .collect(Collectors.toList());

    }
}
