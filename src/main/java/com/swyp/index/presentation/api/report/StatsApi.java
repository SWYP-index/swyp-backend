package com.swyp.index.presentation.api.report;

import com.swyp.index.application.report.StatsService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.report.MonthlyReadingStatsDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "통계 API", description = "독서 통계 관련 API입니다.")
@RestController
@RequestMapping("/api/stats")
@RequiredArgsConstructor
public class StatsApi {

    private final StatsService statsService;

    @Operation(summary = "월별 독서 일수 조회", description = "최근 6개월간 월별로 책을 읽은(기록한) 일수를 조회합니다.")
    @GetMapping("/monthly-reading-days")
    public ResponseEntity<List<MonthlyReadingStatsDto>> getMonthlyReadingDays(@AuthenticationPrincipal CustomPrincipal principal){
        List<MonthlyReadingStatsDto> stats = statsService.getMonthlyReadingDays(principal.getId());
        return ResponseEntity.ok(stats);
    }
}
