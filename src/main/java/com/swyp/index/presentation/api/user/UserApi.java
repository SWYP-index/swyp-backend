package com.swyp.index.presentation.api.user;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.user.TokenService;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.common.CookieUtil;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.global.security.JwtProvider;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.presentation.dto.user.UserResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Tag(name = "사용자 API", description = "인증된 사용자의 정보 조회 및 토큰 관리 API입니다.")
@SecurityRequirement(name = "JWT Authentication")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserApi {

	private final UserRepository userRepository;
	private final JwtProvider jwtProvider;
	private final TokenService tokenService;

	@Operation(summary = "내 정보 조회", description = "현재 로그인된 사용자의 정보를 조회합니다. 요청 성공 시, 새로운 refresh token이 쿠키에 재설정될 수 있습니다.")
	@ApiResponses({
		@ApiResponse(responseCode = "200", description = "사용자 정보 조회 성공"),
		@ApiResponse(responseCode = "401", description = "인증되지 않은 사용자", content = @Content),
		@ApiResponse(responseCode = "404", description = "사용자를 찾을 수 없음", content = @Content)
	})
	@GetMapping("/me")
	public ResponseEntity<UserResponse> getUser(@AuthenticationPrincipal CustomPrincipal principal,
		HttpServletResponse response) {
		User user = userRepository.findById(principal.getId())
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		String refreshToken = jwtProvider.generateRefreshToken(user.getId());

		tokenService.saveRefreshToken(user, refreshToken);

		response.addHeader(HttpHeaders.SET_COOKIE, CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		return ResponseEntity.ok(UserResponse.from(user));
	}

	@PostMapping("/logout")
	@Operation(summary = "로그아웃", description = "사용자의 로그아웃을 처리합니다. 요청 성공 시, 쿠키에 저장된 refresh token이 삭제됩니다." +
		"로그아웃 후에는 기존의 access token과 refresh token이 더 이상 유효하지 않습니다.")
	@ApiResponses({
		@ApiResponse(responseCode = "200", description = "로그아웃 성공"),
		@ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
			content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class)))
	})
	public ResponseEntity<Void> logout(@AuthenticationPrincipal CustomPrincipal principal, HttpServletRequest request,
		HttpServletResponse response) {
		User user = userRepository.findById(principal.getId())
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		tokenService.deleteRefreshToken(user); // 리프레시 토큰 삭제
		tokenService.addAccessTokenToBlacklist(jwtProvider.extractToken(request)); // 액세스 토큰 블랙 리스트 추가

		response.addHeader(HttpHeaders.SET_COOKIE, CookieUtil.createLogoutCookie().toString());

		return ResponseEntity.ok().build();
	}
}