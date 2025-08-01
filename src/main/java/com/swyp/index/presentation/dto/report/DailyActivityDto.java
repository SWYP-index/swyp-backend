package com.swyp.index.presentation.dto.report;

import lombok.Data;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Data
public class DailyActivityDto {
    private LocalDate date;
    private List<BookActivityDto> books = new ArrayList<>();
}
