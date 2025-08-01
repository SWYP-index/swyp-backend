package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.ReadingStartService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequest;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Tag(name = "책 읽기 시작 API", description = "책을 처음으로 책상에 추가하는 API")
@RestController
@RequestMapping("/api/addBookshelf")
@RequiredArgsConstructor
public class ReadingStartApi {

    private final ReadingStartService readingStartService;

    //상세페이지에서 읽기 시작 요청을 보내면, READING 상태의 Bookshelf 에그리거트를 생성하여 반환
    @Operation(
            summary = "책 읽기 시작 (책상에 추가)",
            description = "책 상세페이지 등에서 특정 책(ISBN)을 '읽는 중' 상태로 책상에 등록합니다."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "등록 성공",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = BookshelfResponse.class))),
            @ApiResponse(responseCode = "400", description = "입력값 오류 (예: ISBN 누락)",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "이미 책상에 등록된 책",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping
    public ResponseEntity<BookshelfResponse> addBookToBookshelf(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody BookshelfCreateRequest request
    ) {
        Long currentUserId = principal.getId();
        BookshelfResponse responseDto = readingStartService.addBookToBookshelf(currentUserId, request.getIsbn());
        return ResponseEntity.ok(responseDto);
    }

}
