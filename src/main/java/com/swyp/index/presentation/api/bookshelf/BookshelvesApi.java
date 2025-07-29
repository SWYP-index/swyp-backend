package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.BookshelvesService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequest;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/bookshelves")
@RequiredArgsConstructor
public class BookshelvesApi {

    private final BookshelvesService bookshelvesService;

    //상세페이지에서 읽기 시작 요청을 보내면, READING 상태의 Bookshelf 에그리거트를 생성하여 반환

    @Operation(summary = "책장에 책 추가", description = "새로운 책을 '읽는 중' 상태로 책장에 추가")
    @PostMapping
    public ResponseEntity<BookshelfResponse> addBookToBookshelf(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody BookshelfCreateRequest request
    ) {
        Long currentUserId = principal.getId();
        BookshelfResponse responseDto = bookshelvesService.addBookToBookshelf(currentUserId, request.getIsbn());
        return ResponseEntity.ok(responseDto);
    }

}
