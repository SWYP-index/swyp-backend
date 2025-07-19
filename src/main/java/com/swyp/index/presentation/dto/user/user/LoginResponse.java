package com.swyp.index.presentation.dto.user.user;

import com.swyp.index.domain.user.User;

public record LoginResponse(
	String accessToken,
	UserResponse userResponse
) {
	public static LoginResponse from(String accessToken, User user) {
		return new LoginResponse(
			accessToken, UserResponse.from(user)
		);
	}
}