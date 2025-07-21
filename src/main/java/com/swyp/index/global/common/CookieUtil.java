package com.swyp.index.global.common;

import java.time.Duration;

import org.springframework.http.ResponseCookie;

import jakarta.servlet.http.Cookie;

public class CookieUtil {

	public static ResponseCookie createRefreshTokenCookie(String refreshToken) {
		return ResponseCookie.from("refreshToken", refreshToken)
			.path("/")
			.httpOnly(true)
			.maxAge(Duration.ofDays(7))
			.sameSite("none")         // SameSite 옵션 설정
			.build();
	}

	public static ResponseCookie createAccessTokenCookie(String accessToken) {
		return ResponseCookie.from("accessToken", accessToken)
			.path("/")
			.maxAge(Duration.ofDays(30))
			.sameSite("Lax")         // SameSite 옵션 설정
			.build();
	}
}
