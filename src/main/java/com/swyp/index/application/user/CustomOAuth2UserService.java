package com.swyp.index.application.user;

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

import com.swyp.index.domain.user.GoogleUserInfo;
import com.swyp.index.domain.user.KakaoUserInfo;
import com.swyp.index.domain.user.NaverUserInfo;
import com.swyp.index.domain.user.OAuth2UserInfo;
import com.swyp.index.domain.user.Provider;
import com.swyp.index.domain.user.User;
import com.swyp.index.infrastructure.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final UserRepository userRepository;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		String registrationId = userRequest.getClientRegistration().getRegistrationId().toUpperCase();
		OAuth2UserInfo userInfo = getOAuth2UserInfo(registrationId,
			new DefaultOAuth2UserService().loadUser(userRequest).getAttributes());


		User user = userRepository.findByEmailAndProvider(userInfo.getEmail(), Provider.valueOf(registrationId))
			.map(foundUser -> {
				foundUser.update(userInfo.getName(), registrationId, userInfo.getProviderId());

				return foundUser;
			})
			.orElse(User.fromSocial(registrationId, userInfo));

		User savedUser = userRepository.save(user);

		Map<String, Object> userAttributes = new HashMap<>();

		userAttributes.put("id", String.valueOf(savedUser.getId()));
		userAttributes.put("name", savedUser.getNickname());

		return new DefaultOAuth2User(
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
			userAttributes,
			"name"
		);
	}

	private OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
		return switch (registrationId) {
			case "GOOGLE" -> new GoogleUserInfo(attributes);
			case "NAVER" -> new NaverUserInfo(attributes);
			case "KAKAO" -> new KakaoUserInfo(attributes);

			default -> throw new OAuth2AuthenticationException("지원하지 않는 소셜 로그인입니다: " + registrationId);
		};
	}
}
