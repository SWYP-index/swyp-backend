package com.swyp.index.application.bookshelf;

import java.util.List;
import java.util.stream.Collectors;

import com.swyp.index.presentation.dto.record.EmotionDto;
import com.swyp.index.presentation.dto.record.PageRecordCreateRequest;
import com.swyp.index.presentation.dto.record.PageRecordResponse;
//import com.swyp.index.presentation.dto.record.RecordResponse;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.RecordCreatedEvent;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.EmotionRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class RecordService {

    private final BookshelfRepository bookshelfRepository;
    private final EmotionRepository emotionRepository;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * 이미 '읽는 중'인 책에 새로운 페이지 기록을 추가합니다.
     * @param userId 현재 사용자 ID
     * @param request 페이지 기록 생성 요청 정보 DTO
     * @return 생성된 페이지 기록 정보 DTO
     */
    public PageRecordResponse createPageRecord(Long userId, PageRecordCreateRequest request) {
        Bookshelf bookshelf = bookshelfRepository.findById(request.getBookshelfId())
                .orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

        if (!bookshelf.getUser().getId().equals(userId)) {
            throw new CustomException(ErrorCode.FORBIDDEN_ACCESS);
        }

        List<RecordEmotion> recordEmotions = createRecordEmotions(request.getEmotions());

        PageRecord pageRecord = PageRecord.create(bookshelf, request.getPage(), request.getContent(), recordEmotions);
        bookshelf.addPageRecord(pageRecord);

        eventPublisher.publishEvent(
                RecordCreatedEvent.from(bookshelf.getBook().getId(), pageRecord.getRecordEmotions()));

        return PageRecordResponse.from(pageRecord);
    }

    // EmotionDto를 RecordEmotion 엔티티 리스트로 변환하는 헬퍼 메소드
    private List<RecordEmotion> createRecordEmotions(List<EmotionDto> emotionDtos) {
        if (emotionDtos == null || emotionDtos.isEmpty()) {
            throw new CustomException(ErrorCode.EMOTIONS_NOT_PROVIDED);
        }
        return emotionDtos.stream().map(dto -> {
            Emotion emotion = emotionRepository.findById(dto.getEmotionId()).orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
            return RecordEmotion.builder().emotion(emotion).emotionScore(dto.getScore()).build();
        }).collect(Collectors.toList());
    }
}