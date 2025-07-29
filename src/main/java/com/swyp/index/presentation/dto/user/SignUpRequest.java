package com.swyp.index.presentation.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;

@Schema(description = "회원가입 요청 DTO")
public record SignUpRequest(

		@Schema(description = "가입할 이메일 주소", requiredMode = Schema.RequiredMode.REQUIRED, example = "user@example.com")
		@NotBlank(message = "이메일은 필수 입력 항목입니다.")
		@Email(message = "올바른 이메일 형식이 아닙니다.")
		String email,

		@Schema(description = "비밀번호 (영문, 숫자 포함 8자 이상)", requiredMode = Schema.RequiredMode.REQUIRED, example = "password123")
		@NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
		@Pattern(
				regexp = "^(?=.*[a-zA-Z])(?=.*\\d).{8,}$",
				message = "비밀번호는 영문자와 숫자를 포함하여 8자 이상이어야 합니다."
		)
		String password,

		@Schema(description = "사용할 닉네임 (2~10자, 특수문자 불가)", requiredMode = Schema.RequiredMode.REQUIRED, example = "인덱스유저")
		@NotBlank(message = "닉네임은 필수 입력 항목입니다.")
		@Size(min = 2, max = 10, message = "닉네임은 2자 이상 10자 이하로 입력해주세요.")
		@Pattern(
				regexp = "^[가-힣a-zA-Z0-9]*$",
				message = "닉네임에는 특수문자를 사용할 수 없습니다."
		)
		String nickname

//		@Schema(description = "이메일 인증 완료 후 받은 인증 코드", requiredMode = Schema.RequiredMode.REQUIRED, example = "A4B2C1")
//		@NotBlank(message = "이메일 인증 코드는 필수입니다.")
//		String authCode
) {
}