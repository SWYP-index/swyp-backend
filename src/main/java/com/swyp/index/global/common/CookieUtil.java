package com.swyp.index.global.common;

import java.time.Duration;

import org.springframework.http.ResponseCookie;

public class CookieUtil {

	public static ResponseCookie createRefreshTokenCookie(String refreshToken) {
		return ResponseCookie.from("refreshToken", refreshToken)
			.path("/")
			.httpOnly(true)
			.secure(true)
			.maxAge(Duration.ofDays(7))
			.sameSite("none")
			.build();
	}

	public static ResponseCookie createAccessTokenCookie(String accessToken) {
		return ResponseCookie.from("accessToken", accessToken)
			.path("/")
			.secure(true)
			.maxAge(Duration.ofDays(30))
			.sameSite("none")
			.build();
	}
}
