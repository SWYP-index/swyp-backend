package com.swyp.index.infrastructure.security;

import java.io.IOException;
import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.swyp.index.domain.User.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.User.UserRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

	private final JwtProvider jwtProvider;
	private final RedisTemplate<String, String> redisTemplate;
	private final UserRepository userRepository;
	private final String frontRedirectUrl = "http://localhost:3000/oauth2/redirect";

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException {
		DefaultOAuth2User oauthUser = (DefaultOAuth2User)authentication.getPrincipal();

		String email = oauthUser.getAttribute("email");

		User user = userRepository.findByEmail(email).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		String accessToken = jwtProvider.generateAccessToken(user);
		String refreshToken = jwtProvider.generateRefreshToken(user);

		redisTemplate.opsForValue().set(email, refreshToken, Duration.ofDays(7));

		String redirectUrl = UriComponentsBuilder.fromUriString(frontRedirectUrl)
			.fragment("accessToken=" + accessToken)
			.build().toUriString();

		Cookie cookie = new Cookie("refreshToken", refreshToken);
		cookie.setHttpOnly(true);
		cookie.setPath("/");
		cookie.setMaxAge((int) Duration.ofDays(7).getSeconds());
		// cookie.setSecure(true); // HTTPS 환경에서만 사용

		response.addCookie(cookie);

		response.sendRedirect(redirectUrl);
	}
}
