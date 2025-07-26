package com.swyp.index.global.security;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
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

	private final JwtProvider jwtProvider;
	private final UserRepository userRepository;
	private final Environment environment;

	@Value("${app.redirect-url.local}")
	private String localRedirectUrl;

	@Value("${app.redirect-url.prod}")
	private String prodRedirectUrl;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException {
		DefaultOAuth2User oauthUser = (DefaultOAuth2User)authentication.getPrincipal();

		Long userId = Long.valueOf(Objects.requireNonNull(oauthUser.getAttribute("id")));

		String accessToken = jwtProvider.generateAccessToken(userId);

		String baseUrl = isProdProfileActive() ? prodRedirectUrl : localRedirectUrl;

		String redirectUrl = UriComponentsBuilder.fromUriString(baseUrl)
			.fragment("accessToken=" + accessToken)
			.build().toUriString();

		response.sendRedirect(redirectUrl);
	}

	private boolean isProdProfileActive() {
		return Arrays.stream(environment.getActiveProfiles())
				.anyMatch("prod"::equalsIgnoreCase);
	}
}
