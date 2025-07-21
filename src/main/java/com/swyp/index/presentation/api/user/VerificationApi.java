package com.swyp.index.presentation.api.user;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.application.user.AuthService;
import com.swyp.index.presentation.dto.user.EmailRequest;
import com.swyp.index.presentation.dto.user.EmailVerificationRequest;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth/verification")
@RequiredArgsConstructor
public class VerificationApi {
	private final AuthService authService;

	// 지정된 이메일로 인증 코드를 발송 api
	@PostMapping("/send-code")
	public ResponseEntity<Void> sendVerificationCode(@Valid @RequestBody EmailRequest request){
		authService.sendVerificationCode(request.email());
		return ResponseEntity.ok().build();
	}

	// 이메일과 인증 코드를 받아 유효한지 검증 api
	@PostMapping("/verify-code")
	public ResponseEntity<Void> verifyEmailAndMarkAsVerified(@Valid @RequestBody EmailVerificationRequest request){
		authService.verifyEmailAndMarkAsVerified(request.email(), request.authCode());
		return ResponseEntity.ok().build();
	}
}
