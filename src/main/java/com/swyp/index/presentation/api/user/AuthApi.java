package com.swyp.index.presentation.api.user;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.user.AuthService;
import com.swyp.index.application.user.TokenService;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.common.CookieUtil;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.global.security.JwtProvider;
import com.swyp.index.presentation.dto.user.EmailRequest;
import com.swyp.index.presentation.dto.user.EmailVerificationRequest;
import com.swyp.index.presentation.dto.user.LoginRequest;
import com.swyp.index.presentation.dto.user.LoginResponse;
import com.swyp.index.presentation.dto.user.SignUpRequest;

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
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Tag(name= "인증 API", description = "사용자 회원가입, 로그인, 로그아웃, 이메일 인증, 중복 확인 기능을 제공합니다.")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class AuthApi {

	private final AuthService authService;
	private final TokenService tokenService;
	private final JwtProvider jwtProvider;

	@Operation(summary = "회원가입", description = "이메일 인증 코드 부분을 이메일,비밀번호,닉네임을 받아 회원가입을 처리합니다.")
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

		tokenService.saveRefreshToken(user, refreshToken);

		response.addHeader(HttpHeaders.SET_COOKIE, CookieUtil.createRefreshTokenCookie(refreshToken).toString());

		return ResponseEntity.ok(LoginResponse.from(jwtProvider.generateAccessToken(user.getId()), user));
	}

	@Operation(summary = "로그아웃", description = "서버의 refresh token을 삭제하고 클라이언트의 쿠키를 만료시켜 로그아웃 처리를 합니다.")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "로그아웃 성공"),
			@ApiResponse(responseCode = "401", description = "인증되지 않은 사용자", content = @Content)
	})
	@SecurityRequirement(name = "JWT Authentication")
	@PostMapping("/logout")
	public ResponseEntity<Void> logout(@AuthenticationPrincipal CustomPrincipal principal, HttpServletResponse response) {
		authService.logout(principal.getId());

		response.addHeader(HttpHeaders.SET_COOKIE,CookieUtil.createLogoutCookie().toString());

		return ResponseEntity.ok().build();
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

	@Operation(summary = "닉네임 중복 확인", description = "가입 가능한 닉네임인지 검사합니다.")
	@ApiResponse(responseCode = "200", description = "available: true(가능), false(불가능)")
	@GetMapping("/check/nickname")
	public ResponseEntity<Map<String, Boolean>> checkNickname(
			@RequestParam String nickname
	){
		boolean available = authService.isNicknameAvailable(nickname);
		return ResponseEntity.ok(Map.of("available", available));
	}

	@Operation(summary = "이메일 중복 확인", description = "가입 가능한 이메일인지 검사합니다.")
	@ApiResponse(responseCode = "200", description = "available: true(가능), false(불가능)")
	@GetMapping("/check/email")
	public ResponseEntity<Map<String, Boolean>> checkEmail(
			@RequestParam String email
	){
		boolean available = authService.isEmailAvailable(email);
		return ResponseEntity.ok(Map.of("available", available));
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
