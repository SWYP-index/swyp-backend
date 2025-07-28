package com.swyp.index.application.record;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.emotion.Emotion;
import com.swyp.index.domain.pagerecord.PageRecord;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.recordemotion.RecordEmotion;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.*;
import com.swyp.index.presentation.dto.record.RecordCreateRequestDto;
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
    private final BookshelfRepository bookshelfRepository;
    private final EmotionRepository emotionRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;

    //새로운 페이지 기록을 생성
    //사용자와 책에 대한 Bookshelf가 없으면 새로 생성하고, 있으면 기존 bookshelf에 기록 추가
    public void createPageRecord(Long userId, RecordCreateRequestDto requestDto) {
        // 1. 요청에 필요한 사용자, 책 엔티티를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        Book book = bookRepository.findByIsbn(requestDto.getIsbn())
                .orElseThrow(() -> new IllegalArgumentException("해당 ISBN의 책을 찾을 수 없습니다."));

        // 2. 사용자와 책으로 Bookshelf를 찾고, 없으면 'READING' 상태로 새로 생성합니다.
        Bookshelf bookshelf = bookshelfRepository.findByUserAndBook(user, book)
                .orElseGet(() -> {
                    // Bookshelf가 없다는 것은 '새로 읽기 시작'하는 경우를 의미합니다.
                    Bookshelf newBookshelf = Bookshelf.builder()
                            .user(user)
                            .book(book)
                            .status(ReadingStatus.READING)
                            .build();
                    return bookshelfRepository.save(newBookshelf);
                });

        // 3. 비즈니스 규칙 검증: 이미 '다 읽음' 처리된 책에는 기록을 추가할 수 없습니다.
        if (bookshelf.getStatus() == ReadingStatus.FINISHED) {
            throw new IllegalStateException("이미 다 읽은 책에는 기록을 추가할 수 없습니다.");
        }

        // 4. 새로운 PageRecord 엔티티를 생성합니다.
        PageRecord newPageRecord = PageRecord.builder()
                .bookshelf(bookshelf)
                .page(requestDto.getPage())
                .content(requestDto.getContent())
                .build();

        // 5. 요청받은 감정/점수 목록으로 RecordEmotion 엔티티 리스트를 생성합니다.
        List<RecordEmotion> recordEmotions = requestDto.getEmotions().stream()
                .map(emotionDto -> {
                    Emotion emotion = emotionRepository.findById(emotionDto.getEmotionId())
                            .orElseThrow(() -> new IllegalArgumentException("해당 감정을 찾을 수 없습니다. ID: " + emotionDto.getEmotionId()));
                    return RecordEmotion.builder()
                            .emotion(emotion)
                            .emotionScore(emotionDto.getScore())
                            .build();
                }).collect(Collectors.toList());

        // 6. PageRecord에 생성된 RecordEmotion 리스트를 추가합니다.
        newPageRecord.addRecordEmotions(recordEmotions);

        // 7. PageRecord를 저장합니다. Cascade 설정에 의해 RecordEmotion도 함께 저장됩니다.
        pageRecordRepository.save(newPageRecord);

        // 8. 만약 요청된 상태가 '다 읽음'이라면, Bookshelf의 상태와 완독 날짜를 변경합니다.
        if (requestDto.getStatus() == ReadingStatus.FINISHED) {
            bookshelf.finishBook();;
        }
    }
}
