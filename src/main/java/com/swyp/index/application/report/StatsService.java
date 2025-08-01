package com.swyp.index.application.report;

import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.PageRecordRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.report.MonthlyReadingStatsDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StatsService {
    private final UserRepository userRepository;
    private final PageRecordRepository pageRecordRepository;

    public List<MonthlyReadingStatsDto> getMonthlyReadingDays(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(()-> new CustomException(ErrorCode.USER_NOT_FOUND));

        //조회 기간 설정(최근 6개월)
        LocalDateTime end = LocalDateTime.now();
        LocalDateTime start = end.minusMonths(6).withDayOfMonth(1).toLocalDate().atStartOfDay();

        //DB에서 해당 기간의 모든 기록 조회
        List<PageRecord> records = pageRecordRepository.findAllByBookshelfUserAndCreatedAtBetween(user, start, end);

        //월별로 그룹화하고, 각 월마다 기록이 있는 날짜의 중복을 제거하여 개수를 셈
        Map<YearMonth, Long> daysPerMonth = records.stream()
                .collect(Collectors.groupingBy(
                        record-> YearMonth.from(record.getCreatedAt()),
                        Collectors.mapping(
                                record->record.getCreatedAt().toLocalDate(),
                                Collectors.collectingAndThen(
                                        Collectors.toSet(),
                                        set-> (long) set.size()
                                )
                        )
                ));

        //DTO 리스트로 변환하여 반환
        return daysPerMonth.entrySet().stream()
                .map(entry->new MonthlyReadingStatsDto(
                        entry.getKey().getYear(),
                        entry.getKey().getMonthValue(),
                        entry.getValue()))
                .sorted((a,b)-> YearMonth.of(a.getYear(), a.getMonth()).compareTo(YearMonth.of(b.getYear(), b.getMonth())))
                .collect(Collectors.toList());
    }
}
