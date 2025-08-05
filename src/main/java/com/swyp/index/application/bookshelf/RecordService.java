package com.swyp.index.application.bookshelf;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.*;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.*;
import com.swyp.index.presentation.dto.record.*;
//import com.swyp.index.presentation.dto.record.RecordResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class RecordService {

    private final BookshelfRepository bookshelfRepository;
    private final BookRepository bookRepository;
    private final UserRepository userRepository;
    private final EmotionRepository emotionRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final PageRecordRepository pageRecordRepository;

    /**
     * 읽는 중 페이지 기록 추가
     */
    public PageRecordResponse createPageRecord(Long userId, PageRecordCreateRequest req) {
        // 1) 사용자, 책 확인
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        Book book = bookRepository.findByIsbn(req.getIsbn())
                .orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

        // 2) 반드시 이미 등록된 Bookshelf만 사용
        Bookshelf shelf = bookshelfRepository
                .findByUserAndBook(user, book)
                .orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

        // 3) 완독된 책이면 기록 불가
        if (shelf.getStatus() == ReadingStatus.FINISHED) {
            throw new CustomException(ErrorCode.CANNOT_RECORD_FINISHED_BOOK);
        }

        // 5) 감정 변환 전
        List<EmotionDto> emotionDtos = req.getEmotions();

        // 5) 감정 변환
        List<RecordEmotion> ems = Collections.emptyList();
        if(req.getEmotions() != null && !req.getEmotions().isEmpty()) {
            ems = emotionDtos.stream()
                    .filter(dto->dto.getEmotionId() != 0L)
                    .map(dto -> {
                        Emotion e = emotionRepository.findById(dto.getEmotionId())
                                .orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
                        return RecordEmotion.builder()
                                .emotion(e)
                                .emotionScore(dto.getScore())
                                .build();
                    })
                    .collect(Collectors.toList());
        }


        // 6) PageRecord 생성 & 연관관계
        PageRecord pr = PageRecord.create(shelf, req.getPage(), req.getContent(), ems);
        // PageRecord 직접 저장
        PageRecord savedPr = pageRecordRepository.save(pr);
        shelf.addPageRecord(pr);

        // 7) 저장 (cascade ALL)
        bookshelfRepository.save(shelf);


        // 8) 이벤트 발행
        if(!pr.getRecordEmotions().isEmpty()) {
            eventPublisher.publishEvent(
                    RecordCreatedEvent.from(book.getId(), pr.getRecordEmotions())
            );
        }

        // 9) 응답 DTO
        return PageRecordResponse.from(savedPr);
    }


    /**
     * 완독 처리 및 최종 감상 기록
     */
    public CompletionRecordResponse createCompletionRecord(Long userId, CompletionRecordCreateRequest req) {
        // 1) User, Book 조회
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        Book book = bookRepository.findByIsbn(req.getIsbn())
                .orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

        // 2) Bookshelf 조회
        Bookshelf shelf = bookshelfRepository.findByUserAndBook(user, book)
                .orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

        // 3) 이미 완독된 책인지 검사
        if (shelf.getStatus() == ReadingStatus.FINISHED) {
            throw new CustomException(ErrorCode.CANNOT_RECORD_FINISHED_BOOK);
        }

        // 4) FINISHED 상태로 전환 및 최종 감상 저장
        shelf.finish(req.getFinalNote());

        // 감정 변환
        List<RecordEmotion> ems = Collections.emptyList();
        if(req.getEmotions() != null && !req.getEmotions().isEmpty()) {
            ems = req.getEmotions().stream()
                    .map(dto -> {
                        Emotion e = emotionRepository.findById(dto.getEmotionId())
                                .orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
                        return RecordEmotion.builder()
                                .emotion(e)
                                .emotionScore(dto.getScore())
                                .build();
                    })
                    .collect(Collectors.toList());
        }

        // PageRecord 생성
        PageRecord pr = PageRecord.create(shelf, null, req.getContent(), ems);
        shelf.addPageRecord(pr);
        PageRecord savedPr = pageRecordRepository.save(pr);
        // 저장
        bookshelfRepository.save(shelf);

        // 이벤트 발행
        if(!pr.getRecordEmotions().isEmpty()) {
            eventPublisher.publishEvent(
                    RecordCreatedEvent.from(book.getId(), savedPr.getRecordEmotions())
            );
        }

        return CompletionRecordResponse.from(savedPr, shelf);
    }
}