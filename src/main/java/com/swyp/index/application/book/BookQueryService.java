package com.swyp.index.application.book;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookStats;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.emotion.EmotionType;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.infrastructure.repository.BookshelfRepository;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.book.BookEmotionSearchResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class BookQueryService {

	private final BookRepository bookRepository;
	private final BookshelfRepository bookshelfRepository;

	public BookEmotionSearchResponse getBooksByEmotion(String emotionName, int startIndex) {
		Long emotionId = EmotionType.getIdByName(emotionName);

		List<Book> books = bookRepository.findBooksByEmotionIdOrderByEmotionScoreSumDesc(emotionId,
			PageRequest.of(startIndex - 1, 10));

		List<BookDto> bookDtos = new ArrayList<>();

		for (Book book: books) {
			List<BookStats> bookStats = bookRepository.findTopByBookIdOrderByEmotionScoreSumDesc(
				book.getId(), PageRequest.of(0, 3));

			bookDtos.add(BookDto.from(book, bookStats));
		}

		return new BookEmotionSearchResponse(startIndex, bookDtos);
	}

	public BookDto getBookDetail(String isbn) {
		Book book = bookRepository.findByIsbn(isbn)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		List<BookStats> BookStats = bookRepository.findAllByBookIdOrderByEmotionScoreSumDesc(
			book.getId());

		return BookDto.from(book, BookStats);
	}

	public Optional<Bookshelf> getUserStats(User user, String isbn) {
		Book book = bookRepository.findByIsbn(isbn)
			.orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		return bookshelfRepository.findByUserAndBook(user, book);
	}
}
