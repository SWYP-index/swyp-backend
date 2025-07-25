package com.swyp.index.presentation.api.book;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.book.BookSearchService;
import com.swyp.index.presentation.dto.book.BookSearchResponse;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/books")
@RequiredArgsConstructor
public class BookApi {

	private final BookSearchService bookSearchService;

	@GetMapping("/search")
	public ResponseEntity<?> searchBooks(String title, int startIndex) {
		BookSearchResponse bookSearchResponse = bookSearchService.searchBooks(title, startIndex);

		return ResponseEntity.ok(bookSearchResponse);
	}
}
