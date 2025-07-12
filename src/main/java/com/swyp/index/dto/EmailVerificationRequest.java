package com.swyp.index.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record EmailVerificationRequest(
        @NotBlank @Email
        String email,

        @NotBlank
        String code
) {
}
