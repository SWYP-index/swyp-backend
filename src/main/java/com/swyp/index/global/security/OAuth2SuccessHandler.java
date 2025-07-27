package com.swyp.index.global.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import com.swyp.index.global.common.CookieUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.swyp.index.infrastructure.user.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

//	private final JwtProvider jwtProvider;
//	private final UserRepository userRepository;
//	private final Environment environment;
//
//	@Value("${app.redirect-url.local}")
//	private String localRedirectUrl;
//
//	@Value("${app.redirect-url.prod}")
//	private String prodRedirectUrl;
//
//	@Override
//	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//		Authentication authentication) throws IOException {
//		DefaultOAuth2User oauthUser = (DefaultOAuth2User)authentication.getPrincipal();
//
//		Long userId = Long.valueOf(Objects.requireNonNull(oauthUser.getAttribute("id")));
//
//		String accessToken = jwtProvider.generateAccessToken(userId);
//
//		String baseUrl = isProdProfileActive() ? prodRedirectUrl : localRedirectUrl;
//
//		String redirectUrl = UriComponentsBuilder.fromUriString(baseUrl)
//			.fragment("accessToken=" + accessToken)
//			.build().toUriString();
//
//		response.sendRedirect(redirectUrl);
//		System.out.println(">>> Active Profiles: " + Arrays.toString(environment.getActiveProfiles()));
//		System.out.println(">>> Redirect URL: " + baseUrl);
//	}
//
//	private boolean isProdProfileActive() {
//		return Arrays.stream(environment.getActiveProfiles())
//				.anyMatch("prod"::equalsIgnoreCase);
//	}

	private final JwtProvider jwtProvider;
	// Spring Security가 OAuth2 인증 요청을 세션에 저장하고 로드할 때 사용하는 표준 저장소입니다.
	private final HttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository;

	@Value("${app.redirect-url.prod}") // 프론트엔드가 redirect_uri를 안 보냈을 때를 대비한 기본값
	private String defaultRedirectUrl;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
										Authentication authentication) throws IOException {
		DefaultOAuth2User oauthUser = (DefaultOAuth2User) authentication.getPrincipal();
		Long userId = Long.valueOf(Objects.requireNonNull(oauthUser.getAttribute("id")));

		// 1. accessToken & refreshToken 발급
		String accessToken = jwtProvider.generateAccessToken(userId);
		String refreshToken = jwtProvider.generateRefreshToken(userId);

		// 2. refreshToken을 HttpOnly Cookie로 설정
		ResponseCookie refreshTokenCookie = CookieUtil.createRefreshTokenCookie(refreshToken);
		response.addHeader("Set-Cookie", refreshTokenCookie.toString());

		// 3. 프론트에서 보낸 redirect_uri
		String requestedRedirectUri = (String) request.getSession().getAttribute("redirect_uri");
		String targetUrl = (requestedRedirectUri != null && !requestedRedirectUri.isBlank())
				? requestedRedirectUri
				: defaultRedirectUrl;

		// 4. accessToken은 URL fragment로 보냄
		String redirectUrl = UriComponentsBuilder.fromUriString(targetUrl)
				.fragment("accessToken=" + accessToken)
				.build().toUriString();

		response.sendRedirect(redirectUrl);
		System.out.println(">>>> [OAuth2SuccessHandler] redirect_uri from session: " + requestedRedirectUri);
		System.out.println(">>>> [OAuth2SuccessHandler] final redirect URL: " + redirectUrl);
	}
}

