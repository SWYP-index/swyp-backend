package com.swyp.index.infrastructure.repository;

import static org.assertj.core.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookFixture;
import com.swyp.index.domain.bookshelf.RecordCreatedEvent.RecordCreatedEventEmotion;

import jakarta.persistence.EntityManager;

@DataJpaTest
class BookRepositoryTest {

	@Autowired
	BookRepository bookRepository;

	@Autowired
	private EntityManager entityManager;

	private final String book1Isbn = "00000000000";
	private final String book2Isbn = "00000000001";
	private List<Book> books;

	@BeforeEach
	void setUp() {
		Book book1 = BookFixture.createBook(book1Isbn);
		Book book2 = BookFixture.createBook(book2Isbn);

		book1.addRecordToStats(List.of(
			new RecordCreatedEventEmotion(1L, 1),
			new RecordCreatedEventEmotion(2L, 2),
			new RecordCreatedEventEmotion(20L, 2)));
		book2.addRecordToStats(List.of(
			new RecordCreatedEventEmotion(1L, 1),
			new RecordCreatedEventEmotion(3L, 3)));

		books = List.of(book1, book2);
	}

	@Test
	void findByIsbn() {
		persistAndClear(books);

		assertThat(bookRepository.findByIsbn(book1Isbn)).isPresent()
			.get()
			.extracting(Book::getIsbn)
			.isEqualTo(book1Isbn);
	}

	@Test
	void findAllByIsbnInWithStats() {
		persistAndClear(books);

		List<Book> foundBooks = bookRepository.findAllByIsbnInWithStats(List.of(book1Isbn, "0987654321"));

		assertThat(foundBooks).hasSize(1);
		assertThat(foundBooks.getFirst().getIsbn()).isEqualTo(book1Isbn);
	}

	@Test
	void findExistingIsbns() {
		persistAndClear(books);

		List<String> existingIsbns = bookRepository.findExistingIsbns(List.of(book1Isbn, "0987654321"));

		assertThat(existingIsbns).hasSize(1);
		assertThat(existingIsbns).containsExactly(book1Isbn);
		assertThat(existingIsbns).doesNotContain("0987654321");
	}

	@Test
	void countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero() {
		persistAndClear(books);

		Long count = bookRepository.countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero(1L);
		Long count2 = bookRepository.countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero(2L);
		Long count4 = bookRepository.countBooksByEmotionIdAndEmotionScoreSumGreaterThanZero(4L);

		assertThat(count).isEqualTo(2);
		assertThat(count2).isEqualTo(1);
		assertThat(count4).isEqualTo(0);
	}

	@Test
	void findBooksByEmotionIdOrderByEmotionScoreSumDescGreaterThanZero() {
		persistAndClear(books);

		List<Book> foundBooks = bookRepository.findBooksByEmotionIdOrderByEmotionScoreSumDescGreaterThanZero(1L,
			PageRequest.of(0, 10));

		assertThat(foundBooks).hasSize(2);
		assertThat(foundBooks.getFirst().getIsbn()).isEqualTo(book1Isbn);

		List<Book> foundBooksByEmotionId2 = bookRepository.findBooksByEmotionIdOrderByEmotionScoreSumDescGreaterThanZero(
			3L, PageRequest.of(0, 10));

		assertThat(foundBooksByEmotionId2).hasSize(1);
		assertThat(foundBooksByEmotionId2.getFirst().getIsbn()).isEqualTo(book2Isbn);
	}

	private void persistAndClear(List<Book> books) {
		bookRepository.saveAll(books);

		entityManager.flush();
		entityManager.clear();
	}
}