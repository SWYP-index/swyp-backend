package com.swyp.index.application.book;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class BookQueryService {

	private final BookRepository bookRepository;
	private final BookshelfRepository bookshelfRepository;

	public List<BookDto> getBooksByEmotion(String emotionName, int startIndex) {
		Long emotionId = EmotionType.getIdByName(emotionName);

		List<Book> books = bookRepository.findBooksByEmotionIdOrderByEmotionScoreSumDescGreaterThanZero(emotionId,
			PageRequest.of(startIndex - 1, 10));

		return books.stream().map(book -> BookDto.from(book, book.getTop3Stats())).collect(Collectors.toList());
	}

	public Long getTotalResultsByEmotion(String emotionName) {
		return bookRepository.countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero(
			EmotionType.getIdByName(emotionName));
	}

	public BookDto getBookDetail(String isbn) {
		Book book = bookRepository.findByIsbnWithStats(isbn).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));
		List<BookStats> BookStats = book.getStatsWithPositiveScore();

		return BookDto.from(book, BookStats);
	}

	public Optional<Bookshelf> getUserStats(User user, String isbn) {
		Book book = bookRepository.findByIsbn(isbn).orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));

		return bookshelfRepository.findByUserAndBook(user, book);
	}

	public List<BookDto> getBookDtosByIsbnIn(List<String> isbns) {
		List<Book> books = bookRepository.findAllByIsbnInWithStats(isbns);

		return books.stream().map(book -> BookDto.from(book, book.getTop3Stats())).collect(Collectors.toList());
	}
}
