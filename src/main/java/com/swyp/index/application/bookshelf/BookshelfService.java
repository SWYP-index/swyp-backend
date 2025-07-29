package com.swyp.index.application.bookshelf;

import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfBookDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class BookshelfService {

    private final BookshelfRepository bookshelfRepository;

    public List<BookshelfBookDto> getFinishedBooks(Long userId){
        LocalDateTime sixMonthsAgo = LocalDateTime.now().minusMonths(6);
        return bookshelfRepository.findFinishedBooksByUserId(userId, sixMonthsAgo);
    }
}