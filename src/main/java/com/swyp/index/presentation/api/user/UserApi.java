package com.swyp.index.presentation.api.user;

import java.util.Map;

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
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Tag(name = "사용자 API", description = "인증된 사용자의 정보 조회 및 토큰 관리 API입니다.")
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
	@SecurityRequirement(name = "JWT Authentication") //이 API는 JWt 인증이 필요함.
	@GetMapping("/me")
	public ResponseEntity<?> getUser(@AuthenticationPrincipal CustomPrincipal principal, HttpServletResponse response) {
		User user = userRepository.findById(principal.getId())
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		String refreshToken = jwtProvider.generateRefreshToken(user.getId());

		response.addHeader(HttpHeaders.SET_COOKIE, CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		return ResponseEntity.ok(UserResponse.from(user));
	}

	@Operation(summary = "Access Token 재발급", description = "쿠키에 담긴 Refresh Token을 사용하여 만료된 Access Token을 재발급받습니다.")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Access Token 재발급 성공",
					content = @Content(schema = @Schema(type = "object", example = "{\"accessToken\": \"new_token_string...\"}"))),
			@ApiResponse(responseCode = "401", description = "Refresh Token이 없거나 유효하지 않음", content = @Content)
	})
	@PostMapping("/refresh")
	public ResponseEntity<?> reissueAccessToken(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();

		String refreshToken = null;

		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if ("refreshToken".equals(cookie.getName())) {
					refreshToken = cookie.getValue();
					break;
				}
			}
		}

		tokenService.validateRefreshToken(refreshToken);

		return ResponseEntity.ok(Map.of("accessToken", tokenService.reissueAccessToken(refreshToken)));
	}
}