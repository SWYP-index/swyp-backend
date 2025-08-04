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

    /**
     * [추가] 특정 책을 '완독' 상태로 변경하고 최종 감상을 기록합니다.
     */
    public CompletionRecordResponse finishBookWithNote(Long userId, CompletionRecordCreateRequest request) {
        Bookshelf bookshelf = bookshelfRepository.findById(request.getBookshelfId())
                .orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

        if (!bookshelf.getUser().getId().equals(userId)) {
            throw new CustomException(ErrorCode.FORBIDDEN_ACCESS);
        }
        //Bookshelf의 상태를(다 읽음) 변경하고, finalNote를 저장함.
        bookshelf.finish(request.getFinalNote());

        //content와 감정들은 별도의 PageRecord로 생성하여 추가
        List<RecordEmotion> recordEmotions = createRecordEmotions(request.getEmotions());
        //페이지가 없는 최종 기록이므로 page 파라미터는 null로 전달.
        PageRecord finalRecord = PageRecord.create(bookshelf,null, request.getContent(), recordEmotions);
        bookshelfRepository.save(bookshelf);


        return CompletionRecordResponse.from(finalRecord,bookshelf);
    }

    // EmotionDto를 RecordEmotion 엔티티 리스트로 변환하는 헬퍼 메소드
    private List<RecordEmotion> createRecordEmotions(List<EmotionDto> emotionDtos) {
        if (emotionDtos == null || emotionDtos.isEmpty()) {
            return new ArrayList<>();
        }
        return emotionDtos.stream().map(dto -> {
            Emotion emotion = emotionRepository.findById(dto.getEmotionId()).orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
            return RecordEmotion.builder().emotion(emotion).emotionScore(dto.getScore()).build();
        }).collect(Collectors.toList());
    }


}