package com.swyp.index.domain.book;

public class BookFixture {

	public static Book createBook(String isbn) {
		Book book = Book.builder()
			.isbn(isbn)
			.isbn13("123-4567890123")
			.bookInfo(new BookInfo("Test Title", "Test Author", "Test Description", "Test Publisher",
				"http://example.com/cover.jpg", null, "Fiction"))
			.build();

		book.initializeStatsIfAbsent();

		return book;
	}
}
