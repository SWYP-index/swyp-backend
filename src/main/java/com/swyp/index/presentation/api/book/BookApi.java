package com.swyp.index.presentation.api.book;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.book.BookFacade;
import com.swyp.index.application.book.BookQueryService;
import com.swyp.index.application.user.UserService;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.book.BookSearchResponse;
import com.swyp.index.presentation.dto.book.StatusResponse;

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

	private final BookFacade bookFacade;
	private final BookQueryService bookQueryService;
	private final UserService userService;

	@Operation(summary = "제목 검색", description = "책 제목과 시작 인덱스로 도서 검색, 시작 인덱스는 1부터 시작하여 페이지네이션을 지원합니다."
		+ "한 페이지당 결과값은 10개이고 검색 결과가 없거나 끝 인덱스를 초과한 경우 빈 리스트를 반환합니다.")
	@GetMapping("/search/title")
	public ResponseEntity<BookSearchResponse> searchBooksByTitle(@RequestParam String keyword,
		@RequestParam int startIndex) {
		return ResponseEntity.ok(bookFacade.fetchBooksByTitleAndStoreIfAbsent(keyword, startIndex));
	}

	@Operation(summary = "감정 검색", description = "감정 이름과 시작 인덱스로 도서 검색, 시작 인덱스는 1부터 시작하여 페이지네이션을 지원합니다."
		+ "한 페이지당 결과값은 10개이고 검색 결과가 없거나 끝 인덱스를 초과한 경우 빈 리스트를 반환합니다. 감정 총점이 높은 순으로 내림차순 정렬됩니다.")
	@GetMapping("/search/emotion")
	public ResponseEntity<BookSearchResponse> searchBooksByEmotion(@RequestParam String keyword,
		@RequestParam int startIndex) {
		List<BookDto> books = bookQueryService.getBooksByEmotion(keyword, startIndex);
		Long totalResults = bookQueryService.getTotalResultsByEmotion(keyword);

		return ResponseEntity.ok(new BookSearchResponse(startIndex, totalResults, books));
	}

	@Operation(summary = "상세 페이지", description = "책 정보, 해당 책의 감정 점수를 내림차순으로 반환")
	@GetMapping("/{isbn}")
	public ResponseEntity<BookDto> getBookDetail(@PathVariable String isbn) {
		return ResponseEntity.ok(bookQueryService.getBookDetail(isbn));
	}

	@Operation(summary = "해당 책의 상태 값", description = "유저가 해당 책에 남긴 상태 값(NONE, WISH, READING, FINISHED)을 반환합니다.")
	@GetMapping("/{isbn}/me/status")
	public ResponseEntity<StatusResponse> getUserStatus(@AuthenticationPrincipal CustomPrincipal principal,
		@PathVariable String isbn) {
		User user = userService.getUser(principal.id());

		String status = bookQueryService.getUserStats(user, isbn)
			.map(bookshelf -> bookshelf.getStatus().name())
			.orElse("NONE");

		return ResponseEntity.ok(new StatusResponse(status));
	}
}
