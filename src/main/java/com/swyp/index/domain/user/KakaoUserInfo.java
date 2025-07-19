package com.swyp.index.domain.user;

import java.util.Map;

@SuppressWarnings("unchecked")
public class KakaoUserInfo implements OAuth2UserInfo{
	private final Map<String, Object> attributes;
	private final Map<String, Object> kakaoAttributes;
	private final Map<String, Object> kakaoAccount;

	public KakaoUserInfo(Map<String, Object> attributes) {
 		this.attributes = attributes;
		this.kakaoAttributes = (Map<String, Object>) attributes.get("kakao_account");
		this.kakaoAccount = (Map<String, Object>) kakaoAttributes.get("profile");
	}

	@Override
	public String getEmail() {
		return (String) kakaoAttributes.get("email");
	}

	@Override
	public String getName() {
		return (String) kakaoAccount.get("nickname");
	}

	@Override
	public String getProviderId() {
		return String.valueOf(attributes.get("id"));
	}
}


