package com.swyp.index.presentation.dto;

import com.swyp.index.domain.User.User;

public record LoginResponse(
	Long userId,
	String email,
	String nickname
) {
	public static LoginResponse from(User user){
		return new LoginResponse(
			user.getId(),
			user.getEmail(),
			user.getNickname()
		);
	}
}