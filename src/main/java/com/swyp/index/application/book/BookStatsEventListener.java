package com.swyp.index.application.book;

import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

import com.swyp.index.domain.bookshelf.RecordCreatedEvent;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class BookStatsEventListener {

	private final BookCommandService bookCommandService;

	@TransactionalEventListener
	public void handleBookRecordCreated(RecordCreatedEvent event) {
		bookCommandService.updateBookStats(event.bookId(), event.emotions());
	}
}
