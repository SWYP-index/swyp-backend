package com.swyp.index.application.report;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.emotion.EmotionType;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.RecordEmotionRepository;
import com.swyp.index.infrastructure.repository.UserEmotionStatProjection;
import com.swyp.index.presentation.dto.book.BookStatsDto;
import com.swyp.index.presentation.dto.report.EmotionRankingResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 사용자 개인의 감정 기록 기반 도서별 감정 비중 분석 서비스
 */
@Service
@RequiredArgsConstructor
public class EmotionAnalysisService {

    private final RecordEmotionRepository recordEmotionRepository;
    private final BookRepository bookRepository;

    /**
     * 특정 사용자와 도서에 대해 감정별 점수 비중을 계산하여 반환
     *
     * @Param userId 사용자 ID
     * @Param isbn 도서 isbn
     * @return 감정별 비중 리스트(0~100%)
     */
    public List<BookStatsDto> getUserBookEmotionStats(Long userId, String isbn){
        // 1. ISBN으로 Book 조회
        Book book = bookRepository.findByIsbn(isbn)
                .orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

        Long bookId = book.getId();

        // 2. 감정별 점수 총합 조회
        List<UserEmotionStatProjection> stats = recordEmotionRepository.findBookEmotionStatsByBookId(userId, bookId);

        // 3. 총점 계산
        int total = stats.stream()
                .mapToInt(UserEmotionStatProjection::getTotalScore)
                .sum();

        if (total == 0) return List.of();

        // 4. 감정별 비중 계산
        List<BookStatsDto> result = new ArrayList<>();
        for (UserEmotionStatProjection s : stats) {
            double percentage = (s.getTotalScore() * 100.0) / total;

            //emotionName으로 emotionId 추출
            EmotionType emotion = EmotionType.fromName(s.getEmotionType());
            result.add(new BookStatsDto(
                    null,      //bookStatsId는 개인 통계라 null
                    emotion.getId(),      //감정 ID
                    emotion.getName(),    //감정 한글 이름
                    Math.round(percentage * 10.0) / 10.0  //소수점 1자리 반 올림
            ));
        }

        return result;
    }


    /**
     * [전체 감정 랭킹] 사용자 감정 점수 합계 기준 상위 3개 반환
     */
    public List<EmotionRankingResponse> getTop3Emotions(Long userId) {
        List<UserEmotionStatProjection> stats = recordEmotionRepository.findTopEmotionsByUserId(userId);

        return stats.stream()
                .limit(3)
                .map(s -> {
                    EmotionType emotion = EmotionType.fromName(s.getEmotionType());
                    return new EmotionRankingResponse(
                            emotion.getId(),
                            emotion.getName(),
                            s.getTotalScore()
                    );
                })
                .toList();
    }
}
