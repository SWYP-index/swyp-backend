package com.swyp.index.application.book;

import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.RecordCreatedEvent;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class BookStatsEventListener {

	private final BookRepository bookRepository;

	@TransactionalEventListener
	public void handleBookRecordCreated(RecordCreatedEvent event) {
		Book book = bookRepository.findById(event.bookId()).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		book.updateStats(event.emotions());
	}
}
