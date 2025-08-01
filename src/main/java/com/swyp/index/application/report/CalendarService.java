package com.swyp.index.application.report;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.PageRecordRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.report.BookActivityDto;
import com.swyp.index.presentation.dto.report.DailyActivityDto;
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

    public List<DailyActivityDto> getMonthlyActivities(Long userId, int year, int month) {
        User user = userRepository.findById(userId)
                .orElseThrow(()->new CustomException(ErrorCode.USER_NOT_FOUND));

        //조회할 날짜 범위 설정
        YearMonth yearMonth = YearMonth.of(year, month);
        LocalDateTime startOfMonth = yearMonth.atDay(1).atStartOfDay();
        LocalDateTime endOfMonth = yearMonth.atEndOfMonth().atTime(23,59,59);

        //해당 기간의 모든 활동 데이터 조회
        List<Bookshelf> startedBooks = bookshelfRepository.findAllByUserAndCreatedAtBetween(user, startOfMonth, endOfMonth);
        List<Bookshelf> finishedBooks = bookshelfRepository.findAllByUserAndFinishedAtBetween(user, endOfMonth, startOfMonth);
        List<PageRecord> pageRecords = pageRecordRepository.findRecordsWithEmotionByUserAndDate(user, startOfMonth, endOfMonth);

        //날짜를 기준으로 데이터를 종합할 Map 생성
        Map<LocalDate, Map<Long, BookActivityDto>> activitiesByDate = new TreeMap<>();

        //기록일 처리
        for(PageRecord record : pageRecords){
            LocalDate date = record.getCreatedAt().toLocalDate();
            Bookshelf bookshelf = record.getBookshelf();

            Map<Long, BookActivityDto> booksOnDate = activitiesByDate.computeIfAbsent(date, k -> new HashMap<>());
            BookActivityDto bookActivity = booksOnDate.computeIfAbsent(bookshelf.getId(), k -> BookActivityDto.from(bookshelf));

            record.getRecordEmotions().forEach(re->bookActivity.getEmotionsId().add(re.getEmotion().getId()));
        }

        //독서 시작일 처리
        for(Bookshelf bookshelf : startedBooks){
            LocalDate date = bookshelf.getCreatedAt().toLocalDate();
            Map<Long, BookActivityDto> booksOnDate = activitiesByDate.computeIfAbsent(date, k -> new HashMap<>());
            BookActivityDto bookActivity = booksOnDate.computeIfAbsent(bookshelf.getId(), k -> BookActivityDto.from(bookshelf));
            bookActivity.setStartDate(true);
        }

        //독서 완료일 처리
        for(Bookshelf bookshelf : finishedBooks){
            LocalDate date = bookshelf.getFinishedAt().toLocalDate();
            Map<Long, BookActivityDto> booksOnDate = activitiesByDate.computeIfAbsent(date, k -> new HashMap<>());
            BookActivityDto bookActivity = booksOnDate.computeIfAbsent(bookshelf.getId(), k -> BookActivityDto.from(bookshelf));
            bookActivity.setFinishDate(true);
        }
        return activitiesByDate.entrySet().stream()
                .map(entry->{
                    DailyActivityDto dailyDto = new DailyActivityDto();
                    dailyDto.setDate(entry.getKey());
                    dailyDto.setBooks(new ArrayList<>(entry.getValue().values()));
                    return dailyDto;
                })
                .collect(Collectors.toList());
    }
}
