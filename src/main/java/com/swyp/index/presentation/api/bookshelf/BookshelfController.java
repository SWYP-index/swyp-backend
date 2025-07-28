package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequestDto;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponseDto;
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
public class BookshelfController {

    private final BookshelfService bookshelfService;

    @PostMapping
    public ResponseEntity<BookshelfResponseDto> addBookToBookshelf(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody BookshelfCreateRequestDto requestDto
    ) {
        Long currentUserId = principal.getId();
        Bookshelf savedBookshelf = bookshelfService.addBookToBookshelf(currentUserId, requestDto.getIsbn());

        BookshelfResponseDto responseDto = BookshelfResponseDto.of(savedBookshelf);

        // 201 Created 대신 200 OK를 반환하도록 수정
        return ResponseEntity.ok(responseDto);
    }
}
