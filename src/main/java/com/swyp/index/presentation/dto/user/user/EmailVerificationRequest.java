package com.swyp.index.presentation.dto.user.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record EmailVerificationRequest(
	@NotBlank @Email
	String email,

	@NotBlank
	String authCode
) {
}