package com.swyp.index.application.bookshelf;


import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelves;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelvesRepository;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class BookshelvesService {

    private final BookshelvesRepository bookshelvesRepository;
    private final UserRepository userRepository;
    private final BookRepository bookRepository;
    // 사용자의 책장에 새로운 책을 READING 상태로 추가.
    public BookshelfResponse addBookToBookshelf(Long userId, String isbn) {
        //  사용자(User)와 책(Book) 엔티티를 조회합니다.
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        Book book = bookRepository.findByIsbn(isbn)
                .orElseThrow(() -> new IllegalArgumentException("해당 ISBN의 책을 찾을 수 없습니다."));

        if(bookshelvesRepository.existsByUserAndBook(user, book)){
            throw new IllegalStateException("이미 책장에 추가된 책입니다.");
        }
        Bookshelves newBookshelves = Bookshelves.startReading(user,book);
        Bookshelves savedBookshelves = bookshelvesRepository.save(newBookshelves);
        return BookshelfResponse.of(savedBookshelves);
    }


}
