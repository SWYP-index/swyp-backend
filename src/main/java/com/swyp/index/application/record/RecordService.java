package com.swyp.index.application.record;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelves;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.bookshelf.RecordEmotion;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.*;
import com.swyp.index.presentation.dto.record.RecordCreateRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class RecordService {

    private final PageRecordRepository pageRecordRepository;
    private final BookshelvesRepository bookshelvesRepository;
    private final EmotionRepository emotionRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;

    //새로운 페이지 기록을 생성
    //사용자와 책에 대한 Bookshelf가 없으면 새로 생성하고, 있으면 기존 bookshelf에 기록 추가
    public PageRecord createPageRecord(Long userId, RecordCreateRequest request) {
        // 1. 요청에 필요한 사용자, 책 엔티티를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        Book book = bookRepository.findByIsbn(request.getIsbn())
                .orElseThrow(() -> new IllegalArgumentException("해당 ISBN의 책을 찾을 수 없습니다."));

        //책장 조회 혹은 생성
        Bookshelves bookshelves = bookshelvesRepository.findByUserAndBook(user, book)
                .orElseGet(()-> bookshelvesRepository.save(
                        Bookshelves.startReading(user,book)
                ));

        //RecordEmotion 리스트 변환
        List<RecordEmotion> recordEmotions = request.getEmotions().stream()
                .map(emotionDto -> {
                    Emotion emotion = emotionRepository.findById(emotionDto.getEmotionId())
                            .orElseThrow(()->new IllegalArgumentException(
                                    "해당 감정을 찾을 수 없습니다. ID: " + emotionDto.getEmotionId()));
                    return RecordEmotion.builder()
                            .emotion(emotion)
                            .emotionScore(emotionDto.getScore())
                            .build();
                }).collect(Collectors.toList());

        PageRecord pageRecord = PageRecord.create(
                bookshelves,
                request.getPage(),
                request.getContent(),
                recordEmotions
        );
        bookshelves.addPageRecord(pageRecord);
        bookshelvesRepository.save(bookshelves);

        //finished 상태 호출 시 완독 처리
        if (request.getStatus() == ReadingStatus.FINISHED) {
            bookshelves.finish();
        }
        return pageRecord;
    }
}
