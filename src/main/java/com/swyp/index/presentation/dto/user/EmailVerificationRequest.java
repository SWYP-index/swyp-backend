package com.swyp.index.presentation.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.context.annotation.Configuration;
@Schema(description = "이메일 인증 요청 DTO")
public record EmailVerificationRequest(
		@Schema(description = "인증을 진행할 이메일 주소", requiredMode = Schema.RequiredMode.REQUIRED, example = "user@example.com")
		@NotBlank @Email
		String email,

		@Schema(description = "이메일로 발송된 인증 코드", requiredMode = Schema.RequiredMode.REQUIRED, example = "A4B2C1")
		@NotBlank
		String authCode
) {
}