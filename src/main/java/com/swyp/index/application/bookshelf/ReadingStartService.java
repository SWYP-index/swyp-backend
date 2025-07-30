package com.swyp.index.application.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class ReadingStartService {

    private final BookshelfRepository bookshelfRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;

    // 사용자의 책장에 새로운 책을 READING 상태로 추가.
    public BookshelfResponse addBookToBookshelf(Long userId, String isbn) {
        //  사용자(User)와 책(Book) 엔티티를 조회합니다.
        User user = userRepository.findById(userId).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
        Book book = bookRepository.findByIsbn(isbn).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

        if (bookshelfRepository.existsByUserAndBook(user, book)) {
            throw new CustomException(ErrorCode.BOOKSHELF_ALREADY_EXISTS);
        }
        Bookshelf newBookshelf = Bookshelf.startReading(user, book);
        Bookshelf savedBookshelf = bookshelfRepository.save(newBookshelf);
        return BookshelfResponse.of(savedBookshelf);
    }


}
