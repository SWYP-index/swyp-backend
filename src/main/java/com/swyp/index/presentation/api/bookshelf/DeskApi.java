package com.swyp.index.presentation.api.bookshelf;

import com.swyp.index.application.bookshelf.DeskService;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import com.swyp.index.presentation.dto.bookshelf.DeskBookDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "책상 API", description = "책상에 올린 도서 관련 API입니다.")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/desk")
public class DeskApi {

    private final DeskService deskService;
    private final UserRepository userRepository;

    @Operation(summary = "읽고 있는 책 목록 조회", description = "현재 '읽고 있음(READING)' 상태로 책상에 등록된 도서들을 조회합니다.\n" + "사용자는 JWT 쿠키 인증을 기반으로 식별됩니다.")

    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "조회 성공", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = DeskBookDto.class)))), @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자", content = @Content(schema = @Schema(implementation = ErrorResponse.class))), @ApiResponse(responseCode = "404", description = "유저 정보 없음", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))})

    //현재 읽고 있는 책(READING)에 해당하는 도서 목록 조회
    @GetMapping("/reading")
    public ResponseEntity<List<DeskBookDto>> getReadingBooks(@AuthenticationPrincipal CustomPrincipal principal) {
        Long userId = principal.getId();
        return ResponseEntity.ok(deskService.getReadingBooks(userId));

    }
}
