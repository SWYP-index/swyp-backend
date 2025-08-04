package com.swyp.index.presentation.api.report;

import com.swyp.index.application.report.EmotionAnalysisService;
import com.swyp.index.application.report.ReadingReportService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.book.UserBookEmotionStatDto;
import com.swyp.index.presentation.dto.report.EmotionRankingResponse;
import com.swyp.index.presentation.dto.report.ReadingReportResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
@Tag(name = "독서 리포트 API", description = "읽는 중 + 완독한 책의 감정 분석 리포트를 반환합니다.")
@SecurityRequirement(name = "JWT Authentication")
public class ReadingReportApi {

    private final ReadingReportService readingReportService;
    private final EmotionAnalysisService emotionAnalysisService;

    /**
     * 사용자 리포트 목록 조회 (책상 + 책장 감정 통계 포함)
     */
    @GetMapping
    @Operation(summary = "사용자 독서 리포트 조회", description = "읽는 중 + 완독한 책의 감정 분석 리포트(감정 점수 비율)를 반환합니다.")
    public ResponseEntity<List<ReadingReportResponse>> getUserReadingReports(
            @AuthenticationPrincipal CustomPrincipal principal
    ) {
        Long userId = principal.id();
        List<ReadingReportResponse> reports = readingReportService.getUserReadingReport(userId);
        return ResponseEntity.ok(reports);
    }

    /**
     * 전체 감정 랭킹 TOP3
     */
    @GetMapping("/ranking")
    @Operation(summary = "전체 기록 감정 랭킹 조회(TOP 3)", description = "책과 무관하게 사용자 감정 점수 총합 기준 상위 3개의 감정을 반환합니다.")
    public ResponseEntity<List<EmotionRankingResponse>> getTopEmotions(
            @AuthenticationPrincipal CustomPrincipal principal
    ) {
        Long userId = principal.id();
        List<EmotionRankingResponse> ranking = emotionAnalysisService.getTop3Emotions(userId);
        return ResponseEntity.ok(ranking);
    }
}
