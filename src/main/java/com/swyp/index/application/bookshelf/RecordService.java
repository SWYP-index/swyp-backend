package com.swyp.index.application.bookshelf;

import java.util.Collections;
import java.util.Comparator;
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

        //완독된 책이면 기록 불가
        if(shelf.getStatus()== ReadingStatus.FINISHED){
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

    /**
     * 특정 페이지 기록 단건 조회
     */
    @Transactional(readOnly = true)
    public PageRecordResponse getPageRecord(Long userId, Long recordId){
        PageRecord pageRecord = findRecordById(recordId);
        checkRecordOwnership(userId, pageRecord);
        return PageRecordResponse.from(pageRecord);
    }

    /**
     * 페이지 기록 수정
     */
    @Transactional
    public void updatePageRecord(Long userId, Long recordId, PageRecordUpdateRequest req) {
        PageRecord pageRecord = findRecordById(recordId);
        checkRecordOwnership(userId, pageRecord);
        pageRecord.update(req.getPage(), req.getContent());
        updateEmotionsForRecord(pageRecord, req.getEmotions());
    }

    /**
     * 페이지 기록 삭제
     */
    @Transactional
    public void deletePageRecord(Long userId, Long recordId){
        PageRecord pageRecord = findRecordById(recordId);
        checkRecordOwnership(userId, pageRecord);
        //삭제할 기록의 부모인 Bookshelf를 가져온다
        Bookshelf bookshelf = pageRecord.getBookshelf();
        //부모의 리스트에서 먼저 제거하여 연관관계를 끊어준다.
        bookshelf.removePageRecord(pageRecord);

        pageRecordRepository.delete(pageRecord);
    }


    /**
     * 완독 기록 조회
     */
    @Transactional(readOnly = true)
    public CompletionRecordResponse getCompletionRecord(Long userId, Long bookshelfId) {
        Bookshelf bookshelf = findBookshelfById(bookshelfId);
        checkBookshelfOwnership(userId, bookshelf); // Bookshelf의 소유권 확인

        PageRecord completionRecord = findCompletionRecordByBookshelf(bookshelf);

        return CompletionRecordResponse.from(completionRecord, bookshelf);
    }

    /**
     * 완독 기록 수정
     */
    @Transactional
    public void updateCompletionRecord(Long userId, Long bookshelfId, CompletionRecordUpdateRequest req) {
        Bookshelf bookshelf = findBookshelfById(bookshelfId);
        checkBookshelfOwnership(userId, bookshelf);
        PageRecord completionRecord = findCompletionRecordByBookshelf(bookshelf);

        bookshelf.updateFinalNote(req.getFinalNote());
        completionRecord.update(null, req.getContent());
        updateEmotionsForRecord(completionRecord, req.getEmotions());
    }

    /**
     * 완독 기록 삭제 (완독 취소)
     */
    @Transactional
    public void deleteCompletionRecord(Long userId, Long bookshelfId) {
        Bookshelf bookshelf = findBookshelfById(bookshelfId);
        checkBookshelfOwnership(userId, bookshelf);

        PageRecord completionRecord = findCompletionRecordByBookshelf(bookshelf);

        //db에서 삭제하기전에 bookshelf의 자식 목록에서 먼저 제거
        bookshelf.removePageRecord(completionRecord);

        //이제 db에서 기록을 삭제
        pageRecordRepository.delete(completionRecord);

        // Bookshelf 상태를 READING으로 되돌리고 관련 정보 초기화
        bookshelf.cancelFinish();
    }

    private PageRecord findRecordById(Long recordId){
        return pageRecordRepository.findById(recordId)
                .orElseThrow(()-> new CustomException(ErrorCode.RECORD_NOT_FOUND));
    }

    private Bookshelf findBookshelfById(Long bookshelfId) {
        return bookshelfRepository.findById(bookshelfId)
                .orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));
    }

    //기록의 소유권을 확인하는 private 헬퍼 메서드
    private void checkRecordOwnership(Long userId, PageRecord pageRecord) {
        if (!pageRecord.getBookshelf().getUser().getId().equals(userId)) {
            throw new CustomException(ErrorCode.UNAUTHORIZED_ACCESS);
        }
    }

    private void checkBookshelfOwnership(Long userId, Bookshelf bookshelf) {
        if (!bookshelf.getUser().getId().equals(userId)) {
            throw new CustomException(ErrorCode.UNAUTHORIZED_ACCESS);
        }
    }

    private PageRecord findCompletionRecordByBookshelf(Bookshelf bookshelf) {
        // 먼저 책의 상태가 finished인지 확인
        if (bookshelf.getStatus() != ReadingStatus.FINISHED) {
            // FINISHED 상태가 아니면 완독 기록이 존재할 수 없으므로 에러를 발생시킵니다.
            throw new CustomException(ErrorCode.COMPLETION_RECORD_NOT_FOUND);
        }
        // finished 상태인 경우에만, 페이지가 null인 기록을 찾는다.
        return bookshelf.getPageRecords().stream()
                .filter(record -> record.getPage() == null)
                .max(Comparator.comparing(PageRecord::getCreatedAt))
                .orElseThrow(() -> new CustomException(ErrorCode.RECORD_NOT_FOUND));
    }

    private List<RecordEmotion> convertDtosToEmotions(List<EmotionDto> dtos) {
        if (dtos == null || dtos.isEmpty()) {
            return Collections.emptyList();
        }
        return dtos.stream()
                .map(dto -> {
                    Emotion e = emotionRepository.findById(dto.getEmotionId())
                            .orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
                    return RecordEmotion.builder().emotion(e).emotionScore(dto.getScore()).build();
                })
                .collect(Collectors.toList());
    }

    private void updateEmotionsForRecord(PageRecord record, List<EmotionDto> dtos) {
        record.getRecordEmotions().clear();
        if (dtos != null && !dtos.isEmpty()) {
            record.addRecordEmotions(convertDtosToEmotions(dtos));
        }
    }

}