package com.swyp.index.presentation.api.bookshelf;


import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.domain.user.Provider;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfBookDto;
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

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/bookshelf")
@Tag(name = "책장 API", description = "완독 도서 관리 API입니다.")
public class BookShelfApi {
    private final BookshelfService bookshelfService;
    private final UserRepository userRepository;

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
    public ResponseEntity<List<BookshelfBookDto>> getFinishedBooks(@AuthenticationPrincipal OAuth2User oAuth2User){

        //인증된 사용자 이메일 추출
        if(oAuth2User == null){
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }
        String email = oAuth2User.getAttribute("email");
        Provider provider = oAuth2User.getAttribute("provider");
        if(email == null || email.isEmpty() || provider == null){
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }

        //유저 정보 조회
        User user = userRepository.findByEmailAndProvider(email, provider)
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        //완독한 책 조회
        List<BookshelfBookDto> finishedBooks = bookshelfService.getFinishedBooks(user.getId());

        return ResponseEntity.ok(finishedBooks);

    }
}
