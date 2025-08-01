package com.swyp.index.application.bookshelf;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;

import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class BookshelfService {

    private final BookshelfRepository bookshelfRepository;

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


}