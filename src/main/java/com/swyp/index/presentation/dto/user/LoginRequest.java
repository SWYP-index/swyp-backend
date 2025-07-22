package com.swyp.index.presentation.dto.user;


import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "로그인 요청 DTO")
public record LoginRequest(

		@Schema(description = "가입된 이메일 주소", requiredMode = Schema.RequiredMode.REQUIRED, example = "user@example.com")
		@NotBlank @Email
		String email,

		@Schema(description = "비밀번호", requiredMode = Schema.RequiredMode.REQUIRED, example = "password1234")
		@NotBlank
		String password
) {
}