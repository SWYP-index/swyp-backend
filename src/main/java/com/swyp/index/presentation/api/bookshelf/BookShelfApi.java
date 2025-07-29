package com.swyp.index.presentation.api.bookshelf;


import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfBookDto;
import com.swyp.index.presentation.dto.bookshelf.BookshelfCreateRequest;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
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

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/bookshelf")
@Tag(name = "책장 API", description = "완독 도서 관리 API입니다.")
public class BookShelfApi {
    private final BookshelfService bookshelfService;

    @Operation(
            summary = "완독 도서 목록 조회",
            description = "현재 상태가 'Finished'인 도서만 반환합니다.\n" +
                    "사용자는 JWT 쿠키 인증을 기반으로 식별됩니다."
    )

    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = BookshelfBookDto.class))
                    )),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "유저 정보 없음",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })

    //FINISHED에 해당하는 도서 목록 조회
    @GetMapping("/finished")
    public ResponseEntity<List<BookshelfBookDto>> getFinishedBooks(@AuthenticationPrincipal CustomPrincipal principal){

        Long userId = principal.getId();
        return ResponseEntity.ok(bookshelfService.getFinishedBooks(userId));

    }

}
