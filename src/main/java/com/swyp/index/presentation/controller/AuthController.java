package com.swyp.index.presentation.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.User.TokenService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

	private final TokenService tokenService;

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
}
