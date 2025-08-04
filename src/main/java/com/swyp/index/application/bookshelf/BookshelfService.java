package com.swyp.index.application.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookshelfRepository;

import com.swyp.index.infrastructure.repository.EmotionRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import com.swyp.index.presentation.dto.record.CompletionRecordCreateRequest;
import com.swyp.index.presentation.dto.record.CompletionRecordResponse;
import com.swyp.index.presentation.dto.record.EmotionDto;
//import com.swyp.index.presentation.dto.record.RecordResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
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

    //책상의 책 목록(읽는 중인 책)을 조회하는 기능
    @Transactional(readOnly = true)
    public List<BookshelfSummaryDto> getDeskBooks(Long userId) {
        List<Bookshelf> readingShelf = bookshelfRepository.findReadingBooksByUserId(userId);
        return readingShelf.stream()
                .map(BookshelfSummaryDto::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<String> getReadingIsbns(Long userId) {
        return bookshelfRepository.findReadingBooksByUserId(userId).stream()
                .map(shelf -> shelf.getBook().getIsbn())
                .collect(Collectors.toList());
    }


}