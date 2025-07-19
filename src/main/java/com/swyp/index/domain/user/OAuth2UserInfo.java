package com.swyp.index.domain.user;

public interface OAuth2UserInfo {
	String getEmail();
	String getName();
	String getProviderId();
}