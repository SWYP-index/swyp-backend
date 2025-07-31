package com.swyp.index.application.book;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class BookCommandService {

	private final BookRepository bookRepository;
	private final BookshelfRepository bookshelfRepository;

	public void updateBookStatus(User user, String isbn, String status) {
		Book book = bookRepository.findByIsbn(isbn).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		Bookshelf bookshelf = bookshelfRepository.findByUserAndBook(user, book)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOKSHELF_NOT_FOUND));

		bookshelf.updateStatus(status);
	}
}
