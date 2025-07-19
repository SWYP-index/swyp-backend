package com.swyp.index.global.common;

import java.time.Duration;

import jakarta.servlet.http.Cookie;

public class CookieUtil {

	public static Cookie createRefreshTokenCookie(String refreshToken) {
		Cookie cookie = new Cookie("refreshToken", refreshToken);

		cookie.setHttpOnly(true);
		cookie.setPath("/");
		cookie.setMaxAge((int) Duration.ofDays(7).getSeconds());
		// cookie.setSecure(true); // HTTPS 환경일 경우 주석 해제

		return cookie;
	}
}
