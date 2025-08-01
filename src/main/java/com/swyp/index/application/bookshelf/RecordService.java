package com.swyp.index.application.bookshelf;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.bookshelf.RecordCreatedEvent;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.*;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.EmotionRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.record.RecordCreateRequest;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class RecordService {

	private final ApplicationEventPublisher eventPublisher;
    private final BookshelfRepository bookshelfRepository;
    private final EmotionRepository emotionRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;

    //새로운 페이지 기록을 생성
    //사용자와 책에 대한 Bookshelf가 없으면 새로 생성하고, 있으면 기존 bookshelf에 기록 추가
    public PageRecord createPageRecord(Long userId, RecordCreateRequest request) {

        //유효성 검증 로직 추가
        if(request.getStatus() == ReadingStatus.READING && request.getPage() == null) {
            //읽는 중 일때 페이지 번호가 없으면 에러 발생
            throw new CustomException(ErrorCode.PAGE_NUMBER_REQUIRED);
        }
        if(request.getEmotions() == null || request.getEmotions().isEmpty()){
            throw new CustomException(ErrorCode.EMOTIONS_NOT_PROVIDED);
        }

        // 요청에 필요한 사용자, 책 엔티티를 조회합니다.
        User user = userRepository.findById(userId).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        Book book = bookRepository.findByIsbn(request.getIsbn()).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

        //책장 조회 혹은 생성
        Bookshelf bookshelf = bookshelfRepository.findByUserAndBook(user, book).orElseGet(() -> bookshelfRepository.save(Bookshelf.startReading(user, book)));

        //완독한 책인지 검증하는 로직 추가
        if(bookshelf.getStatus() ==ReadingStatus.FINISHED){
            throw new CustomException(ErrorCode.CANNOT_RECORD_FINISHED_BOOK);
        }

        //RecordEmotion 리스트 변환
        List<RecordEmotion> recordEmotions = request.getEmotions().stream().map(emotionDto -> {
            Emotion emotion = emotionRepository.findById(emotionDto.getEmotionId()).orElseThrow(() -> new CustomException(ErrorCode.EMOTION_NOT_FOUND));
            return RecordEmotion.builder().emotion(emotion).emotionScore(emotionDto.getScore()).build();
        }).collect(Collectors.toList());

        PageRecord pageRecord = PageRecord.create(bookshelf, request.getPage(), request.getContent(), recordEmotions);
        bookshelf.addPageRecord(pageRecord);
        bookshelfRepository.save(bookshelf);

        //다 읽음 상태일 경우
        if (request.getStatus() == ReadingStatus.FINISHED) {
            bookshelf.finish(request.getFinalNote());
        }

		eventPublisher.publishEvent(
			RecordCreatedEvent.from(book.getId(), pageRecord.getRecordEmotions()));

        return pageRecord;
    }
}
