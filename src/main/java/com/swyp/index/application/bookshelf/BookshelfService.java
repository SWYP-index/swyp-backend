package com.swyp.index.application.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookshelfRepository;

import com.swyp.index.infrastructure.repository.EmotionRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import com.swyp.index.presentation.dto.record.*;
//import com.swyp.index.presentation.dto.record.RecordResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BookshelfService {

    private final BookshelfRepository bookshelfRepository;
    private final EmotionRepository emotionRepository;

    @Transactional(readOnly=true)
    public List<BookshelfSummaryDto> getFinishedBooks(Long userId) {
        LocalDateTime sixMonthsAgo = LocalDateTime.now().minusMonths(6);
        //repository에서는 entity 리스트를 받는다.
        List<Bookshelf> finishedShelf = bookshelfRepository.findFinishedBooksByUserId(userId, sixMonthsAgo);
        //service에서 entity 리스트를 dto 리스트로 변환한다.
        return finishedShelf.stream()
                .map(BookshelfSummaryDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<String> getFinishedIsbns(Long userId) {
        LocalDateTime sixMonthsAgo = LocalDateTime.now().minusMonths(6);
        return bookshelfRepository.findFinishedBooksByUserId(userId, sixMonthsAgo).stream()
                .map(shelf -> shelf.getBook().getIsbn())
                .distinct()
                .toList();
    }


    //책상의 책 목록(읽는 중인 책)을 조회하는 기능
    @Transactional(readOnly = true)
    public List<BookshelfSummaryDto> getDeskBooks(Long userId) {
        List<Bookshelf> readingShelf = bookshelfRepository.findReadingBooksByUserId(userId);
        return readingShelf.stream()
                .map(BookshelfSummaryDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<BookshelfSummaryDto> getDeskBooks(Long userId, int limit) { // 최대 N권
        return bookshelfRepository.findReadingBooksByUserId(userId).stream()
                .limit(limit)
                .map(BookshelfSummaryDto::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<String> getReadingIsbns(Long userId) {
        return bookshelfRepository.findReadingBooksByUserId(userId).stream()
                .map(shelf -> shelf.getBook().getIsbn())
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<String> getReadingIsbns(Long userId, int limit) { // 최대 N권
        return bookshelfRepository.findReadingBooksByUserId(userId).stream()
                .limit(limit)
                .map(shelf -> shelf.getBook().getIsbn())
                .toList();
    }

    /**
     * 특정 책에 대한 모든 페이지/완독 기록을 조회한다.
     */

    @Transactional(readOnly = true)
    public List<UnifiedRecordResponse> getRecordsByBookshelf(Long bookshelfId, Long userId) {
        // 1. 책장 정보 조회 및 사용자 권한 확인
        Bookshelf bookshelf = bookshelfRepository.findByIdWithPageRecords(bookshelfId)
                .orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

        if (!bookshelf.getUser().getId().equals(userId)) {
            throw new CustomException(ErrorCode.UNAUTHORIZED_ACCESS);
        }

        List<PageRecord> allRecords = bookshelf.getPageRecords();
        if (allRecords.isEmpty()) {
            return Collections.emptyList();
        }

        bookshelfRepository.findPageRecordsWithEmotions(allRecords);

        List<UnifiedRecordResponse> responseList = new ArrayList<>();
        // 책의 상태를 기준으로 기록 타입 구분
        if (bookshelf.getStatus() == ReadingStatus.FINISHED) {
            // 완독 상태이면, page가 null인 '완독 기록'을 먼저 찾습니다.
            PageRecord completionRecord = allRecords.stream()
                    .filter(record -> record.getPage() == null)
                    .findFirst()
                    .orElseThrow(() -> new CustomException(ErrorCode.COMPLETION_RECORD_NOT_FOUND)); // 완독인데 완독기록이 없는 에러

            //  '완독 기록'을 FINISHED 상태 DTO로 변환하여 추가합니다.
            responseList.add(UnifiedRecordResponse.fromCompletionRecord(completionRecord, bookshelf));

            // '완독 기록'을 제외한 나머지 모든 기록을 READING 상태 DTO로 변환합니다.
            for (PageRecord record : allRecords) {
                if (record.getId().equals(completionRecord.getId())) {
                    continue; // 완독 기록은 건너뜁니다.
                }
                responseList.add(UnifiedRecordResponse.fromPageRecord(record));
            }
        } else {
            //상태가 reading인 경우, page 필드가 null이든, 아니든, 모든 기록을 페이지 기록 DTO로 변환
            for (PageRecord record : allRecords) {
                responseList.add(UnifiedRecordResponse.fromPageRecord(record));
            }
        }

        //전체 기록을 날짜 기준 최신 순으로 정렬
        responseList.sort(Comparator.comparing(UnifiedRecordResponse::getCreatedAt).reversed());

        return responseList;
    }
}