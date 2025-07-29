package com.swyp.index.application.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class BookshelfService {

    private final BookshelfRepository bookshelfRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;
    // 사용자의 책장에 새로운 책을 READING 상태로 추가.
    public BookshelfResponse addBookToBookshelf(Long userId, String isbn) {
        //  사용자(User)와 책(Book) 엔티티를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        Book book = bookRepository.findByIsbn(isbn)
                .orElseThrow(() -> new IllegalArgumentException("해당 ISBN의 책을 찾을 수 없습니다."));

        if(bookshelfRepository.existsByUserAndBook(user, book)){
            throw new IllegalStateException("이미 책장에 추가된 책입니다.");
        }
        Bookshelf newBookshelf = Bookshelf.startReading(user,book);
        Bookshelf savedBookshelf = bookshelfRepository.save(newBookshelf);
        return BookshelfResponse.of(savedBookshelf);
    }

    //특정 사용자가 최근 6개월 내에 완독한 책 목록 조회
    @Transactional(readOnly = true)
    public List<BookshelfSummaryResponse> getFinishedBooks(Long userId){
        LocalDateTime sixMonthsAgo = LocalDateTime.now().minusMonths(6);
        return bookshelfRepository.findFinishedBooksByUserId(userId, sixMonthsAgo);
    }

    //특정 사용자가 현재 읽고 있는 책 목록을 조회
    @Transactional(readOnly = true)
    public List<BookshelfSummaryResponse> getReadingBooks(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        return bookshelfRepository.findByUserAndStatus(user, ReadingStatus.READING)
                .stream()
                .map(bookshelf -> BookshelfSummaryResponse.from(bookshelf)) // 엔티티를 DTO로 변환
                .collect(Collectors.toList());
    }
}
