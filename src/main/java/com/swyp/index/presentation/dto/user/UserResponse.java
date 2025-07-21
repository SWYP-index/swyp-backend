package com.swyp.index.presentation.dto.user;

import com.swyp.index.domain.user.User;

public record UserResponse(Long userId, String email, String nickname, String provider) {

	public static UserResponse from(User user) {
		return new UserResponse(user.getId(), user.getEmail(), user.getNickname(), user.getProvider().name());
	}
}
