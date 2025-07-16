package com.swyp.index.presentation.dto;

import com.swyp.index.domain.User.User;

public record UserResponse(Long userId, String email, String nickname) {

	public static UserResponse from(User user) {
		return new UserResponse(user.getId(), user.getEmail(), user.getNickname());
	}
}
