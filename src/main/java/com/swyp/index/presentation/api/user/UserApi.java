package com.swyp.index.presentation.api.user;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.user.TokenService;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.common.CookieUtil;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.global.security.JwtProvider;
import com.swyp.index.infrastructure.user.UserRepository;
import com.swyp.index.presentation.dto.user.UserResponse;

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

	@GetMapping("/me")
	public ResponseEntity<?> getUser(Authentication authentication, HttpServletResponse response) {
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		User user = userRepository.findById(Long.valueOf(userDetails.getUsername()))
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		log.info("User found: {}", user.getEmail());

		String refreshToken = jwtProvider.generateRefreshToken(user);

		response.addHeader(HttpHeaders.SET_COOKIE, CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		log.info("Refresh token set in response header: {}", refreshToken);

		return ResponseEntity.ok(UserResponse.from(user));
	}

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