package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.BookRecommendService;
import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import com.swyp.index.presentation.dto.bookshelf.DeskOverviewResponse;
import com.swyp.index.presentation.dto.bookshelf.RecommendedBookDto;
import io.swagger.v3.oas.annotations.Operation;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "책상 API", description = "책상에 올린 도서 관련 API입니다.")
@SecurityRequirement(name = "JWT Authentication")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/desk")
public class DeskApi {

    private final BookshelfService bookshelfService;
    private final BookRecommendService bookRecommendService;

    @Operation(summary = "책상 전체 조회", description = "읽는 중 도서(최대 3권)와 감정 기반 추천 도서를 함께 반환합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = BookshelfSummaryDto.class)))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })

    @GetMapping("/reading")
    public ResponseEntity<DeskOverviewResponse> getDeskBooks(@AuthenticationPrincipal CustomPrincipal principal) {
        Long userId = principal.getId();

        List<BookshelfSummaryDto> readingBooks = bookshelfService.getDeskBooks(userId)
                .stream()
                .limit(3) //최대 3권까지만 응답
                .toList();
        List<RecommendedBookDto> recommendedBooks = bookRecommendService.getRecommendBooksOnly(userId);

        return ResponseEntity.ok(new DeskOverviewResponse(readingBooks, recommendedBooks));
    }

    @Operation(summary = "읽는 중 도서 목록 조회", description = "현재 '읽는 중' 상태인 모든 책의 목록을 반환합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = BookshelfSummaryDto.class)))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })

    @GetMapping("/reading-only")
    public ResponseEntity<List<BookshelfSummaryDto>> getReadingBooksOnly(@AuthenticationPrincipal CustomPrincipal principal) {
        Long userId = principal.getId();
        List<BookshelfSummaryDto> readingBooks = bookshelfService.getDeskBooks(userId);
        return ResponseEntity.ok(readingBooks);
    }
}
