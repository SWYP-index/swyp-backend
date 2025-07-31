package com.swyp.index.presentation.dto.report;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(description = "월별 독서 일수 통계 DTO")
public class MonthlyReadingStatsDto {
    @Schema(description = "연도", example = "2025")
    private final int year;

    @Schema(description = "월", example = "7")
    private final int month;

    @Schema(description = "해당 월에 기록한 총 일수", example = "12")
    private final long readingDays;

    public MonthlyReadingStatsDto(int year, int month, long readingDays) {
        this.year = year;
        this.month = month;
        this.readingDays = readingDays;
    }

}
