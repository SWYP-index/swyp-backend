package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.BookRecommendService;
import com.swyp.index.global.security.CustomPrincipal;
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
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "추천 API", description = "사용자 맞춤 도서 추천 관련 API입니다.")
@SecurityRequirement(name = "JWT Authentication")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/recommendations")
public class BookRecommendApi {

    private final BookRecommendService bookRecommendService;

    @Operation(summary = "사용자 맞춤 도서 추천", description = "사용자의 독서 기록과 감정을 기반으로 도서 5권을 추천합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "추천 성공",
                    content = @Content(mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = RecommendedBookDto.class)))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })

    @GetMapping
    public ResponseEntity<List<RecommendedBookDto>> getRecommendedBooks(@AuthenticationPrincipal CustomPrincipal principal){
        Long userId = principal.getId();
        List<RecommendedBookDto> recommendedBooks = bookRecommendService.getRecommendBooksOnly(userId);
        return ResponseEntity.ok(recommendedBooks);
    }

}
