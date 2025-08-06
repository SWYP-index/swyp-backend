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
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StatsService {
    private final UserRepository userRepository;
    private final PageRecordRepository pageRecordRepository;

    public List<MonthlyReadingStatsDto> getMonthlyReadingDays(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(()-> new CustomException(ErrorCode.USER_NOT_FOUND));
        //기준이 될 현재 연월을 가져옵니다.
        YearMonth currentMonth = YearMonth.now();
        //DB에서 조회할 기간을 설정합니다.
        LocalDateTime end = LocalDateTime.now();
        LocalDateTime start = currentMonth.minusMonths(5).atDay(1).atStartOfDay();
        //  DB에서 해당 기간의 모든 기록을 조회합니다.
        List<PageRecord> records = pageRecordRepository.findAllByBookshelfUserAndCreatedAtBetween(user, start, end);
        Map<YearMonth, Long> readingDaysPerMonth = records.stream()
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
        //  최근 6개월 전체 목록을 만들고, 실제 데이터가 없는 달은 0으로 채워줍니다.
        return IntStream.range(0, 6)
                .mapToObj(i -> currentMonth.minusMonths(5 - i))
                .map(yearMonth -> {
                    // 4번에서 계산한 Map에서 해당 월의 데이터를 가져옵니다. 없으면 기본값 0L을 사용합니다.
                    long readingDays = readingDaysPerMonth.getOrDefault(yearMonth, 0L);
                    return new MonthlyReadingStatsDto(
                            yearMonth.getYear(),
                            yearMonth.getMonthValue(),
                            readingDays
                    );
                })
                .collect(Collectors.toList());
    }

//        //조회 기간 설정(최근 6개월)
//        LocalDateTime end = LocalDateTime.now();
//        LocalDateTime start = end.minusMonths(6).withDayOfMonth(1).toLocalDate().atStartOfDay();
//
//        //DB에서 해당 기간의 모든 기록 조회
//        List<PageRecord> records = pageRecordRepository.findAllByBookshelfUserAndCreatedAtBetween(user, start, end);
//
//        //월별로 그룹화하고, 각 월마다 기록이 있는 날짜의 중복을 제거하여 개수를 셈
//        Map<YearMonth, Long> daysPerMonth = records.stream()
//                .collect(Collectors.groupingBy(
//                        record-> YearMonth.from(record.getCreatedAt()),
//                        Collectors.mapping(
//                                record->record.getCreatedAt().toLocalDate(),
//                                Collectors.collectingAndThen(
//                                        Collectors.toSet(),
//                                        set-> (long) set.size()
//                                )
//                        )
//                ));
//
//        //DTO 리스트로 변환하여 반환
//        return daysPerMonth.entrySet().stream()
//                .map(entry->new MonthlyReadingStatsDto(
//                        entry.getKey().getYear(),
//                        entry.getKey().getMonthValue(),
//                        entry.getValue()))
//                .sorted((a,b)-> YearMonth.of(a.getYear(), a.getMonth()).compareTo(YearMonth.of(b.getYear(), b.getMonth())))
//                .collect(Collectors.toList());
//    }
}
