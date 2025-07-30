package com.swyp.index.application.calendar;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.PageRecordRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.calendar.CalendarResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CalendarService {
    private final BookshelfRepository bookshelfRepository;
    private final UserRepository userRepository;
    private final PageRecordRepository pageRecordRepository;

    public CalendarResponse getCalendarActivities(Long userId, int year, int month) {
        User user = userRepository.findById(userId)
                .orElseThrow(()->new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        //조회할 날짜 범위 설정
        YearMonth yearMonth = YearMonth.of(year, month);
        LocalDateTime startOfMonth = yearMonth.atDay(1).atStartOfDay();
        LocalDateTime endOfMonth = yearMonth.atEndOfMonth().atTime(23,59,59);

        //해당 기간의 모든 활동 데이터 조회
        List<Bookshelf> startedBooks = bookshelfRepository.findAllByUserAndCreatedAtBetween(user, startOfMonth, endOfMonth);
        List<Bookshelf> finishedBooks = bookshelfRepository.findAllByUserAndFinishedAtBetween(user, endOfMonth, startOfMonth);
        List<PageRecord> pageRecords = pageRecordRepository.findRecordsWithEmotionByUserAndDate(user, startOfMonth, endOfMonth);

        //데이터 가공
        Set<LocalDate> startDates = startedBooks.stream()
                .map(bookshelf -> bookshelf.getCreatedAt().toLocalDate())
                .collect(Collectors.toSet());

        Set<LocalDate> finishDates = finishedBooks.stream()
                .map(bookshelf -> bookshelf.getFinishedAt().toLocalDate())
                .collect(Collectors.toSet());

        Map<LocalDate, Set<String>> emotionsByDate = new HashMap<>();
        for(PageRecord record : pageRecords){
            LocalDate recordDate = record.getCreatedAt().toLocalDate();
            //해당 날짜의 감정 Set을 가져오거나 새로 생성
            Set<String> emotions = emotionsByDate.computeIfAbsent(recordDate, k -> new HashSet<>());
            //해당 기록의 모든 감정 이름을 set에 추가
            record.getRecordEmotions().forEach(e->emotions.add(e.getEmotion().getName()));
        }

        return CalendarResponse.builder()
                .startDates(startDates)
                .finishDates(finishDates)
                .emotionsByDate(emotionsByDate)
                .build();
    }
}
