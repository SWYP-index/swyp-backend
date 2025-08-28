package com.swyp.index.presentation.api.wishlist;

import com.swyp.index.application.wishlist.WishlistService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.bookshelf.BookshelfSummaryDto;
import com.swyp.index.presentation.dto.wishlist.WishlistRequest;
import com.swyp.index.presentation.dto.wishlist.WishlistResponseDto;
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
import java.util.Map;

@RestController
@RequestMapping("/api/wishlist")
@RequiredArgsConstructor
@Tag(name = "찜하기 API", description = "도서 찜하기 관련 API")
@SecurityRequirement(name = "JWT Authentication")
public class WishlistApi{
    private final WishlistService wishlistService;

    @Operation(summary = "찜 목록에 도서 추가", description = "특정 도서(ISBN)를 사용자의 찜 목록에 추가합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "찜하기 성공"),
            @ApiResponse(responseCode = "400", description = "입력값 오류 (예: ISBN 누락)", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "존재하지 않는 도서", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping
    public ResponseEntity<Void> addWish(@AuthenticationPrincipal CustomPrincipal principal, @RequestBody WishlistRequest request) {
        wishlistService.addWish(principal.getId(), request.getIsbn());
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "찜 목록에서 도서 삭제", description = "특정 도서(ISBN)를 사용자의 찜 목록에서 삭제합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "찜하기 취소 성공"),
            @ApiResponse(responseCode = "404", description = "찜 목록에 없는 도서", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @DeleteMapping("/{isbn}")
    public ResponseEntity<Void> removeWish(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "삭제할 도서의 ISBN", required = true, example = "9791191891234") @PathVariable String isbn
    ) {
        wishlistService.removeWish(principal.getId(), isbn);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "찜한 도서 목록 조회", description = "현재 사용자가 찜한 모든 책의 목록을 반환합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = WishlistResponseDto.class)))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자")
    })
    @GetMapping
    public ResponseEntity<List<WishlistResponseDto>> getWishlist(@AuthenticationPrincipal CustomPrincipal principal) {
        return ResponseEntity.ok(wishlistService.getWishlist(principal.getId()));
    }

    @Operation(summary = "특정 책의 찜 상태만 확인", description = "특정 책에 대해 현재 사용자의 찜 여부를 true/false로 반환합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(type = "object", example = "{\"wished\": true}"))),
            @ApiResponse(responseCode = "404", description = "존재하지 않는 도서")
    })
    @GetMapping("/status/{isbn}")
    public ResponseEntity<Map<String, Boolean>> checkWishStatus(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "상태를 조회할 도서의 ISBN", required = true, example = "9791191891234") @PathVariable String isbn
    ) {
        boolean isWished = wishlistService.checkWishStatus(principal.getId(), isbn);
        return ResponseEntity.ok(Map.of("wished", isWished));
    }
}
