package com.swyp.index.domain.user;

import java.util.Map;

@SuppressWarnings("unchecked")
public class NaverUserInfo implements OAuth2UserInfo {
	private final Map<String, Object> attributes;

	public NaverUserInfo(Map<String, Object> attributes) {
		this.attributes = (Map<String, Object>) attributes.get("response");
	}

	@Override
	public String getEmail() {
		return (String) attributes.get("email");
	}

	@Override
	public String getName() {
		return (String) attributes.get("name");
	}

	@Override
	public String getProviderId() {
		return (String) attributes.get("id");
	}
}
