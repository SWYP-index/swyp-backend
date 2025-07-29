package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequest;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryResponse;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/bookshelves")
@RequiredArgsConstructor
public class BookshelfApi {

    private final BookshelfService bookshelfService;

    //상세페이지에서 읽기 시작 요청을 보내면, READING 상태의 Bookshelf 에그리거트를 생성하여 반환

    @Operation(summary = "책장에 책 추가", description = "새로운 책을 '읽는 중' 상태로 책장에 추가")
    @PostMapping
    public ResponseEntity<BookshelfResponse> addBookToBookshelf(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody BookshelfCreateRequest request
    ) {
        Long currentUserId = principal.getId();
        BookshelfResponse responseDto = bookshelfService.addBookToBookshelf(currentUserId, request.getIsbn());
        return ResponseEntity.ok(responseDto);
    }

    @Operation(summary = "완독 도서 목록 조회", description = "최근 6개월 내에 완독한 도서 목록을 조회합니다.")
    @GetMapping("/finished")
    public ResponseEntity<List<BookshelfSummaryResponse>> getFinishedBooks(
            @AuthenticationPrincipal CustomPrincipal principal
    ) {
        Long currentUserId = principal.getId();
        List<BookshelfSummaryResponse> finishedBooks = bookshelfService.getFinishedBooks(currentUserId);
        return ResponseEntity.ok(finishedBooks);
    }

    @Operation(summary = "읽고 있는 도서 목록 조회", description = "'읽는 중' 상태인 도서 목록을 조회합니다.")
    @GetMapping("/reading")
    public ResponseEntity<List<BookshelfSummaryResponse>> getReadingBooks(
            @AuthenticationPrincipal CustomPrincipal principal
    ) {
        Long currentUserId = principal.getId();
        List<BookshelfSummaryResponse> readingBooks = bookshelfService.getReadingBooks(currentUserId);
        return ResponseEntity.ok(readingBooks);
    }


}
