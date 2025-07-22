package com.swyp.index.presentation.dto.user;

import com.swyp.index.domain.user.User;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "로그인 성공 응답 DTO")
public record LoginResponse(

		@Schema(description = "서버에서 발급된 Access Token", example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...")
		String accessToken,

		@Schema(description = "로그인한 사용자 정보")
		UserResponse userResponse
) {
	public static LoginResponse from(String accessToken, User user) {
		return new LoginResponse(
				accessToken, UserResponse.from(user)
		);
	}
}