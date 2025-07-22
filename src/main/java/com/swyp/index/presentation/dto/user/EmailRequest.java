package com.swyp.index.presentation.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "이메일 관련 요청 DTO")
public record EmailRequest(
		@Schema(description = "사용자 이메일 주소", requiredMode = Schema.RequiredMode.REQUIRED, example = "test@example.com")
		@NotBlank @Email
		String email
) {
}