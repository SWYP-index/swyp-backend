package com.swyp.index.presentation.dto.user;

import com.swyp.index.domain.user.User;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "사용자 정보 응답 DTO")
public record UserResponse(
		@Schema(description = "사용자 고유 ID", example = "1")
		Long userId,

		@Schema(description = "사용자 이메일", example = "user@example.com")
		String email,

		@Schema(description = "사용자 닉네임", example = "인덱스유저")
		String nickname,

		@Schema(description = "가입 경로 (소셜 로그인 플랫폼 등)", example = "KAKAO")
		String provider
) {

	public static UserResponse from(User user) {
		return new UserResponse(user.getId(), user.getEmail(), user.getNickname(), user.getProvider().name());
	}
}