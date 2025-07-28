package com.swyp.index.application.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class BookshelfService {

    private final BookshelfRepository bookshelfRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;
    // 사용자의 책상에 새로운 책을 READING 상태로 추가.
    public Bookshelf addBookToBookshelf(Long userId, String isbn) {
        // 1. 사용자(User)와 책(Book) 엔티티를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        Book book = bookRepository.findByIsbn(isbn)
                .orElseThrow(() -> new IllegalArgumentException("해당 ISBN의 책을 찾을 수 없습니다."));

        // 2. 이미 책장에 추가된 책인지 확인하여 중복을 방지합니다.
        bookshelfRepository.findByUserAndBook(user, book).ifPresent(b -> {
            throw new IllegalStateException("이미 책장에 추가된 책입니다.");
        });

        // 3. 새로운 Bookshelf 엔티티를 'READING' 상태로 생성합니다.
        Bookshelf newBookshelf = Bookshelf.builder()
                .user(user)
                .book(book)
                .status(ReadingStatus.READING)
                .build();

        // 4. 생성된 Bookshelf를 저장하고 반환합니다.
        return bookshelfRepository.save(newBookshelf);
    }
}
