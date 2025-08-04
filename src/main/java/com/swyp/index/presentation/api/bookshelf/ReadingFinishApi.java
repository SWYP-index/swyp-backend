package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.ReadingFinishService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequest;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "다 읽음 책 가져오는 API", description = "완독한 도서를 책장에 추가하는 API")
@SecurityRequirement(name = "JWT Authentication")
@RestController
@RequestMapping("/api/addFinishBookshelf")
@RequiredArgsConstructor
public class ReadingFinishApi {
    private final ReadingFinishService readingFinishService;

    @Operation(summary = "완독한 책을 책장에 추가", description = "ISBN을 받아 해당 도서를 '다 읽음' 상태로 사용자의 책장에 바로 추가합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "완독 도서 추가 성공",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = BookshelfResponse.class))),
            @ApiResponse(responseCode = "400", description = "요청 데이터 유효성 검사 실패 (ex. ISBN 누락)"),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @ApiResponse(responseCode = "404", description = "제공된 ISBN에 해당하는 도서 정보를 찾을 수 없음"),
            @ApiResponse(responseCode = "409", description = "해당 도서가 이미 책장에 존재함")
    })
    @PostMapping
    public ResponseEntity<BookshelfResponse> addfinishBookToBookshelf(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody BookshelfCreateRequest request
    ){
        Long currentUserId = principal.getId();
        BookshelfResponse responseDto = readingFinishService.addBookAsFinished(currentUserId, request.getIsbn());
        return ResponseEntity.ok(responseDto);
    }
}
