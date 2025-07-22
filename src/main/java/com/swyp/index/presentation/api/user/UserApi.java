package com.swyp.index.presentation.api.user;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
import com.swyp.index.infrastructure.user.UserRepository;
import com.swyp.index.presentation.dto.user.UserResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserApi {

	private final UserRepository userRepository;
	private final JwtProvider jwtProvider;
	private final TokenService tokenService;

	@Operation(summary = "내 정보 조회", description = "액세스 토큰을 이용하여 현재 로그인한 사용자의 정보를 조회합니다.")
	@ApiResponse(responseCode = "200", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserResponse.class)))
	@GetMapping("/me")
	public ResponseEntity<?> getUser(Authentication authentication, HttpServletResponse response) {
		CustomPrincipal principal = (CustomPrincipal)authentication.getPrincipal();

		User user = userRepository.findById(principal.getId())
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		String refreshToken = jwtProvider.generateRefreshToken(user.getId());

		response.addHeader(HttpHeaders.SET_COOKIE, CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		return ResponseEntity.ok(UserResponse.from(user));
	}

	@Operation(summary = "액세스 토큰 재발급", description = "리프레시 토큰을 이용하여 새로운 액세스 토큰을 발급받습니다.")
	@ApiResponse(responseCode = "200", description = "새로운 액세스 토큰 발급 성공", content = @Content(mediaType = "application/json", schema = @Schema(example = """
		{
		  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpJVCL9..."
		}
		""")))
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

		if (refreshToken == null) {
			throw new CustomException(ErrorCode.UNAUTHORIZED);
		}

		return ResponseEntity.ok(Map.of("accessToken", tokenService.reissueAccessToken(refreshToken)));
	}
}