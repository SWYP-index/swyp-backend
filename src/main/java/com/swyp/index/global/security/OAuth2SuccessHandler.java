package com.swyp.index.global.security;

import java.io.IOException;
import java.util.Objects;

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

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException {
		DefaultOAuth2User oauthUser = (DefaultOAuth2User)authentication.getPrincipal();

		Long userId = Long.valueOf(Objects.requireNonNull(oauthUser.getAttribute("id")));

		String accessToken = jwtProvider.generateAccessToken(userId);

		String redirectUrl = UriComponentsBuilder.fromUriString("https://index-pi-nine-40.vercel.app/login/oauth2/success")
			.fragment("accessToken=" + accessToken)
			.build().toUriString();

		response.sendRedirect(redirectUrl);
	}
}
