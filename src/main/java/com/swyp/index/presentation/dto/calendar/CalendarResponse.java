package com.swyp.index.presentation.dto.calendar;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

@Getter
@Builder
@Schema(description = "월별 캘린더 독서 활동 응답 DTO")
public class CalendarResponse {

    @Schema(description = "독서 시작일 목록")
    private Set<LocalDateTime> startDates;
    @Schema(description = "독서 완료일 목록")
    private Set<LocalDateTime> finishDates;

    @Schema(description = "날짜별 기록된 감정 이름 목록")
    private Map<LocalDate, Set<String>> emotionsByDate;
}
