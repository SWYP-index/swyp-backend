package com.swyp.index.presentation.api.book;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.book.BookSearchService;
import com.swyp.index.presentation.dto.book.BookSearchResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

@Tag(name = "도서 검색", description = "감정, 책 제목으로 도서 검색 및 도서의 상세 페이지 API")
@SecurityRequirement(name = "JWT Authentication")
@RestController
@RequestMapping("/api/books")
@RequiredArgsConstructor
public class BookApi {
	private final BookSearchService bookSearchService;

	@Operation(summary = "제목 검색", description = "책 제목과 시작 인덱스를 기반으로 도서 목록 반환, 시작 인덱스 기준으로 페이지네이션")
	@GetMapping("/search")
	public ResponseEntity<BookSearchResponse> searchBooks(String title, int startIndex) {
		BookSearchResponse bookSearchResponse = bookSearchService.searchBooks(title, startIndex);

		return ResponseEntity.ok(bookSearchResponse);
	}
}
