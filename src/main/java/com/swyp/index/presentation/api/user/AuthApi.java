package com.swyp.index.presentation.api.user;

import java.time.Duration;
import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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


@Tag(name= "인증 API", description = "사용자 회원가입, 로그인, 이메일 인증 관련 API입니다.")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthApi {
	
	private final AuthService authService;
	private final JwtProvider jwtProvider;
	private final RedisTemplate<String, String> redisTemplate;

	@Operation(summary = "회원가입", description = "이메일, 비밀번호, 닉네임, 이메일 인증 코드를 받아 회원가입을 처리합니다.")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "회원가입 성공"),
			@ApiResponse(responseCode = "400", description = "입력값 유효성 검사 실패 또는 이메일 미인증", content = @Content),
			@ApiResponse(responseCode = "409", description = "이미 존재하는 이메일 또는 닉네임", content = @Content),
	})
	@PostMapping("/signup")
	public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequest request) {
		authService.signUp(request);

		return ResponseEntity.ok().build();
	}

	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "로그인 성공"),
			@ApiResponse(responseCode = "401", description = "이메일 또는 비밀번호 불일치", content = @Content)
	})
	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
		User user = authService.login(request);

		String refreshToken = jwtProvider.generateRefreshToken(user.getId());

		redisTemplate.opsForValue().set(String.valueOf(user.getId()), refreshToken, Duration.ofDays(7));

		response.addHeader(HttpHeaders.SET_COOKIE,CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		return ResponseEntity.ok(LoginResponse.from(jwtProvider.generateAccessToken(user.getId()), user));
	}

	@Operation(summary = "이메일 인증 코드 발송", description = "지정된 이메일로 6자리 인증 코드를 발송합니다.")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "인증 코드 발송 성공"),
			@ApiResponse(responseCode = "409", description = "이미 가입된 이메일", content = @Content)
	})
	@PostMapping("/verification/send-code")
	public ResponseEntity<Void> sendVerificationCode(@Valid @RequestBody EmailRequest request){
		authService.sendVerificationCode(request.email());
		return ResponseEntity.ok().build();
	}

	@Operation(summary = "이메일 인증 코드 검증", description = "이메일과 인증 코드를 받아 유효성을 검증하고, 성공 시 해당 이메일을 '인증됨' 상태로 변경합니다.")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "이메일 인증 성공"),
			@ApiResponse(responseCode = "400", description = "인증 코드가 일치하지 않음", content = @Content)
	})
	@PostMapping("/verification/verify-code")
	public ResponseEntity<Void> verifyEmailAndMarkAsVerified(@Valid @RequestBody EmailVerificationRequest request){
		authService.verifyEmailAndMarkAsVerified(request.email(), request.authCode());
		return ResponseEntity.ok().build();
	}
}
