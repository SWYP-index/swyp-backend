package com.swyp.index.application.User;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import com.swyp.index.domain.User.GoogleUserInfo;
import com.swyp.index.domain.User.NaverUserInfo;
import com.swyp.index.domain.User.OAuth2UserInfo;
import com.swyp.index.domain.User.User;
import com.swyp.index.infrastructure.User.UserRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		OAuth2UserInfo userInfo = getOAuth2UserInfo(registrationId,
			new DefaultOAuth2UserService().loadUser(userRequest).getAttributes());

		User user = userRepository.findByEmail(userInfo.getEmail())
			.map(foundUser -> {
				foundUser.update(userInfo.getName(), registrationId, userInfo.getProviderId());

				return foundUser;
			})
			.orElse(User.of(userInfo.getEmail(), userInfo.getName(), registrationId, userInfo.getProviderId()));

		User savedUser = userRepository.save(user);

		Map<String, Object> userAttributes = new HashMap<>();
		userAttributes.put("email", savedUser.getEmail());
		userAttributes.put("name", savedUser.getNickname());
		userAttributes.put("provider", savedUser.getProvider().name());
		userAttributes.put("providerId", savedUser.getProviderId());

		return new DefaultOAuth2User(
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
			userAttributes,
			"name"
		);
	}

	private OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
		return switch (registrationId) {
			case "google" -> new GoogleUserInfo(attributes);
			case "naver" -> new NaverUserInfo(attributes);

			default -> throw new OAuth2AuthenticationException("지원하지 않는 소셜 로그인입니다: " + registrationId);
		};
	}
}
