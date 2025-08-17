package com.swyp.index.presentation.api.bookshelf;


import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import com.swyp.index.presentation.dto.record.UnifiedRecordResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/bookshelf")
@Tag(name = "책장 API", description = "완독 도서 관리 API입니다.")
@SecurityRequirement(name = "JWT Authentication")
public class BookShelfApi {
    private final BookshelfService bookshelfService;

    @Operation(summary = "완독 도서 목록 조회", description = "현재 상태가 'Finished'인 도서만 반환합니다.\n" + "사용자는 JWT 쿠키 인증을 기반으로 식별됩니다.")

    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "조회 성공", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = BookshelfSummaryDto.class)))), @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자", content = @Content(schema = @Schema(implementation = ErrorResponse.class))), @ApiResponse(responseCode = "404", description = "유저 정보 없음", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))})

    //FINISHED에 해당하는 도서 목록 조회
    @GetMapping("/finished")
    public ResponseEntity<List<BookshelfSummaryDto>> getFinishedBooks(@AuthenticationPrincipal CustomPrincipal principal) {

        Long userId = principal.getId();
        return ResponseEntity.ok(bookshelfService.getFinishedBooks(userId));

    }

    @Operation(summary = "특정 책의 모든 기록 조회",
            description = "특정 책(bookshelfId)에 대한 모든 페이지 기록과 완독 기록을 최신순으로 조회합니다.\n\n" +
                    "각 기록 객체 안의 'status' 필드를 통해 '페이지 기록(READING)'과 '완독 기록(FINISHED)'을 구분할 수 있습니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = UnifiedRecordResponse.class)))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음 (자신의 책장이 아님)",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "데이터를 찾을 수 없음 (ID에 해당하는 책장이 없거나, 완독 상태인 책의 완독 기록이 없는 경우)",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping("/{bookshelfId}/records")
    public ResponseEntity<List<UnifiedRecordResponse>> getRecordsForBookshelf(
            @Parameter(description = "조회할 책장의 ID", example = "123", required = true)
            @PathVariable Long bookshelfId,
            @AuthenticationPrincipal CustomPrincipal principal) {

        Long userId = principal.getId();
        List<UnifiedRecordResponse> records = bookshelfService.getRecordsByBookshelf(bookshelfId, userId);
        return ResponseEntity.ok(records);
    }

}
