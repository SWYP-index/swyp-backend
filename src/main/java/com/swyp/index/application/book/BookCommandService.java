package com.swyp.index.application.book;

import java.util.HashSet;
import java.util.List;
import java.util.Set;


import com.swyp.index.domain.bookshelf.RecordUpdatedEvent;
import com.swyp.index.infrastructure.repository.PageRecordRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.bookshelf.RecordCreatedEvent.RecordCreatedEventEmotion;
import com.swyp.index.domain.bookshelf.RecordDeletedEvent.RecordDeletedEventEmotion;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.api.AladinSearchResponse;
import com.swyp.index.infrastructure.repository.BookRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class BookCommandService {

	private final BookRepository bookRepository;
	private final PageRecordRepository pageRecordRepository;

	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void updateBookStats(Long bookId, List<RecordCreatedEventEmotion> emotions) {
		Book book = bookRepository.findById(bookId)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		book.addRecordToStats(emotions);

		long uniqueUserCount = pageRecordRepository.countDistinctUsersByBookId(bookId);
		book.updateUserCount(uniqueUserCount);
	}

	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void decreaseBookStats(Long bookId, List<RecordDeletedEventEmotion> emotions) {
		Book book = bookRepository.findById(bookId)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));
		book.removeRecordFromStats(emotions);

		long uniqueUserCount = pageRecordRepository.countDistinctUsersByBookId(bookId);
		book.updateUserCount(uniqueUserCount);
	}

	public void saveBooksIfNotExists(AladinSearchResponse aladinSearchResponse) {
		List<String> isbnList = aladinSearchResponse.items().stream().map(AladinSearchResponse.BookItem::isbn).toList();

		List<String> existingIsbnList = bookRepository.findExistingIsbns(isbnList);
		Set<String> existingIsbnSet = new HashSet<>(existingIsbnList);

		List<Book> newBooks = aladinSearchResponse.items()
			.stream()
			.filter(book -> !existingIsbnSet.contains(book.isbn()))
			.map(Book::from)
			.toList();

		bookRepository.saveAll(newBooks);
	}

	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void recalculateBookStats(Long bookId, List<RecordUpdatedEvent.RecordEmotionInfo> oldEmotions, List<RecordUpdatedEvent.RecordEmotionInfo> newEmotions) {
		Book book = bookRepository.findById(bookId)
				.orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		book.recalculateStats(oldEmotions, newEmotions);

		long uniqueUserCount = pageRecordRepository.countDistinctUsersByBookId(bookId);
		book.updateUserCount(uniqueUserCount);
	}
}
