package com.swyp.index.presentation.api.user;

import java.time.Duration;
import java.util.Map;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.user.AuthService;
import com.swyp.index.application.user.TokenService;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.common.CookieUtil;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.global.security.JwtProvider;
import com.swyp.index.presentation.dto.user.EmailRequest;
import com.swyp.index.presentation.dto.user.EmailVerificationRequest;
import com.swyp.index.presentation.dto.user.LoginRequest;
import com.swyp.index.presentation.dto.user.LoginResponse;
import com.swyp.index.presentation.dto.user.SignUpRequest;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthApi {
	
	private final AuthService authService;
	private final JwtProvider jwtProvider;
	private final RedisTemplate<String, String> redisTemplate;

	@PostMapping("/signup")
	public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequest request) {
		authService.signUp(request);

		return ResponseEntity.ok().build();
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
		User user = authService.login(request);

		String refreshToken = jwtProvider.generateRefreshToken(user);

		redisTemplate.opsForValue().set(String.valueOf(user.getId()), refreshToken, Duration.ofDays(7));

		response.addHeader(HttpHeaders.SET_COOKIE,CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		return ResponseEntity.ok(LoginResponse.from(jwtProvider.generateAccessToken(user), user));
	}

	// 지정된 이메일로 인증 코드를 발송 api
	@PostMapping("/verification/send-code")
	public ResponseEntity<Void> sendVerificationCode(@Valid @RequestBody EmailRequest request){
		authService.sendVerificationCode(request.email());
		return ResponseEntity.ok().build();
	}

	// 이메일과 인증 코드를 받아 유효한지 검증 api
	@PostMapping("/verification/verify-code")
	public ResponseEntity<Void> verifyEmailAndMarkAsVerified(@Valid @RequestBody EmailVerificationRequest request){
		authService.verifyEmailAndMarkAsVerified(request.email(), request.authCode());
		return ResponseEntity.ok().build();
	}
}
