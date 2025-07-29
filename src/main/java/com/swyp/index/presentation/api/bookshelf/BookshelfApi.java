package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequest;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bookshelves")
@RequiredArgsConstructor
public class BookshelfApi {

    private final BookshelfService bookshelfService;

    //상세페이지에서 읽기 시작 요청을 보내면, READING 상태의 Bookshelf 에그리거트를 생성하여 반환

    @PostMapping
    public ResponseEntity<BookshelfResponse> addBookToBookshelf(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody BookshelfCreateRequest request
    ) {
        Long currentUserId = principal.getId();
        Bookshelf savedBookshelf = bookshelfService.addBookToBookshelf(currentUserId, request.getIsbn());
        return ResponseEntity.ok(BookshelfResponse.of(savedBookshelf));
    }
}
