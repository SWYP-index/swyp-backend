package com.swyp.index.presentation.controller;

import java.security.Principal;
import java.util.Arrays;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.User.AuthService;
import com.swyp.index.application.User.TokenService;
import com.swyp.index.infrastructure.security.JwtProvider;
import com.swyp.index.presentation.dto.LoginRequest;
import com.swyp.index.presentation.dto.LoginResponse;
import com.swyp.index.presentation.dto.SignUpRequest;
import com.swyp.index.presentation.dto.UserInfoResponse;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

	private final TokenService tokenService;
	private final AuthService authService;
	private final JwtProvider jwtProvider;

	@PostMapping("/refresh")
	public ResponseEntity<?> refreshAccessToken(HttpServletRequest request) {
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
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token not found");
		}

		String newAccessToken = tokenService.refreshAccessToken(refreshToken);

		return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
	}

	@PostMapping("/signup")
	public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequest request){
		authService.signUp(request);
		return ResponseEntity.ok().build();
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(
		@Valid @RequestBody LoginRequest request,
		HttpServletResponse response
	){
		//서비스에서 로그인 처리 후 토큰과 사용자 정보를 모두 받아옴.
		Map<String, Object> result = authService.login(request);
		Map<String, String> tokens = (Map<String, String>) result.get("tokens");
		LoginResponse userInfo = (LoginResponse) result.get("userInfo");

		//토큰을 쿠키에 설정한다.
		addCookie(response, "accessToken", tokens.get("accessToken"), 900000);
		addCookie(response, "refreshToken", tokens.get("refreshToken"), 604800000);

		return ResponseEntity.ok(userInfo);
	}

	@GetMapping("/me")
	public ResponseEntity<UserInfoResponse> getCurrentUser(Principal principal){
		if(principal == null){
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}

		UserInfoResponse userInfo = authService.getCurrentUserInfo(principal.getName());

		return ResponseEntity.ok(userInfo);
	}

	private void addCookie(HttpServletResponse response, String nickname, String value, long maxAgeMs){
		ResponseCookie cookie = ResponseCookie.from(nickname, value)
			.path("/")
			.httpOnly(true)
			.secure(true)
			.maxAge(maxAgeMs/1000)
			.build();
		response.addHeader("Set-Cookie", cookie.toString());
	}

	//쿠키 만료시키는 메서드
	private void expireCookie(HttpServletResponse response, String nickname){
		ResponseCookie cookie = ResponseCookie.from(nickname, "")
			.path("/")
			.httpOnly(true)
			.secure(true)
			.maxAge(0)
			.build();
		response.addHeader("Set-Cookie", cookie.toString());
	}

	private String extractCookie(HttpServletRequest request, String name){
		if(request.getCookies() == null) return null;
		return Arrays.stream(request.getCookies())
			.filter(c -> name.equals(c.getName()))
			.map(Cookie::getValue)
			.findFirst()
			.orElse(null);
	}
}
