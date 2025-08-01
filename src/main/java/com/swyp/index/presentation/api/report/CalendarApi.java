package com.swyp.index.presentation.api.report;


import com.swyp.index.application.report.CalendarService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "캘린더 API", description = "월별 독서 활동을 조회하는 API입니다.")
@RestController
@RequestMapping("/api/calendar")
@RequiredArgsConstructor
public class CalendarApi {

    private final CalendarService calendarService;

    @Operation(summary = "월별 독서 활동 조회", description = "특정 연월의 독서 시작일, 완료일, 기록일 및 감정 정보를 조회합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(schema = @Schema(implementation = CalendarResponse.class))),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 (예: 연도 또는 월 누락)",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping
    public ResponseEntity<CalendarResponse> getCalendarActivities(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "조회할 연도", required = true) @RequestParam("year") int year,
            @Parameter(description = "조회할 월", required = true) @RequestParam("month") int month
            ){

            Long userId = principal.getId();
            CalendarResponse response = calendarService.getCalendarActivities(userId, year, month);
            return ResponseEntity.ok(response);
    }
}
