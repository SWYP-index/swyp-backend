package com.swyp.index.presentation.dto.report;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;
import java.util.Map;
import java.util.Set;

@Getter
@Builder
@Schema(description = "월별 캘린더 독서 활동 응답 DTO")
public class CalendarResponse {

    @Schema(description = "독서 시작일 목록", example = "[\"2025-07-09\", \"2025-07-22\"]")
    private Set<LocalDate> startDates;

    @Schema(description = "독서 완료일 목록", example = "[\"2025-07-17\"]")
    private Set<LocalDate> finishDates;

    @Schema(description = "날짜별 기록된 감정 이름 목록",
            example = "{\"2025-07-11\":[\"감동\",\"위로\"], \"2025-07-12\":[\"슬픔\"]}")
    private Map<LocalDate, Set<String>> emotionsByDate;
}