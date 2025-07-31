package com.swyp.index.presentation.api.book;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.book.BookSearchService;
import com.swyp.index.presentation.dto.book.BookEmotionSearchResponse;
import com.swyp.index.presentation.dto.book.BookTitleSearchResponse;

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

	@Operation(summary = "제목 검색", description = "책 제목과 시작 인덱스로 도서 검색, 시작 인덱스는 1부터 시작하여 페이지네이션을 지원합니다."
		+ "한 페이지당 결과값은 10개이고 검색 결과가 없거나 끝 인덱스를 초과한 경우 빈 리스트를 반환합니다.")
	@GetMapping("/search/title")
	public ResponseEntity<BookTitleSearchResponse> searchBooks(String keyword, int startIndex) {
		BookTitleSearchResponse bookTitleSearchResponse = bookSearchService.searchBooksByTitle(keyword, startIndex);

		return ResponseEntity.ok(bookTitleSearchResponse);
	}


	@Operation(summary = "감정 검색", description = "감정 이름과 시작 인덱스로 도서 검색, 시작 인덱스는 1부터 시작하여 페이지네이션을 지원합니다."
		+ "한 페이지당 결과값은 10개이고 검색 결과가 없거나 끝 인덱스를 초과한 경우 빈 리스트를 반환합니다.")
	@GetMapping("/search/emotion")
	public ResponseEntity<BookEmotionSearchResponse> searchBooksByEmotion(String keyword, int startIndex) {
		BookEmotionSearchResponse bookEmotionSearchResponse = bookSearchService.searchBooksByEmotion(keyword,
			startIndex);

		return ResponseEntity.ok(bookEmotionSearchResponse);
	}
}
