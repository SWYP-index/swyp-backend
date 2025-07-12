package com.swyp.index.dto;

import jakarta.validation.constraints.*;

public record SignUpRequest(
        @NotBlank(message = "이메일은 필수 입력 항목입니다.")
        @Email(message = "올바른 이메일 형식이 아닙니다.")
        String email,

        @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
        @Pattern(//최소 한 개의 영문자가 포함 및 최소 한개의 숫자가 포함
                regexp = "^(?=.*[a-zA-Z])(?=.*\\d).{8,}$",
                message = "비밀번호는 영문자와 숫자를 포함하여 8자 이상이어야 합니다."
        )
        String password,

        @NotBlank(message = "닉네임은 필수 입력 항목입니다.")
        @Size(min = 2, max = 10, message = "닉네임은 2자 이상 10자 이하로 입력해주세요.")
        @Pattern(
                regexp = "^[가-힣a-zA-Z0-9]*$",
                message = "닉네임에는 특수문자를 사용할 수 없습니다."
        )
        String nickname,

        //이메일 인증이 완료되면, 이 필드에 인증 코드를 담아 보냅니다.
        @NotBlank(message = "이메일 인증 코드는 필수입니다.")
        String authCode,

        //true인지 검증, 반드시 체크해야 하는 항목에 사용됨.
        @AssertTrue(message = "약관에 동의해야 회원가입이 가능합니다.")
        boolean termsAgreed
) {
}
