package com.swyp.index.controller;

import com.swyp.index.dto.EmailRequest;
import com.swyp.index.dto.EmailVerificationRequest;
import com.swyp.index.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/verification")
@RequiredArgsConstructor

public class VerificationController {
    private final AuthService authService;

    //지정된 이메일로 인증 코드를 발송 api
    @PostMapping("/send-code")
    public ResponseEntity<Void> sendVerificationCode(@Valid @RequestBody EmailRequest request){
        authService.sendVerificationCode(request.email());
        return ResponseEntity.ok().build();
    }

    //이메일과 인증 코드를 받아 유효한지 검증 api
    @PostMapping("/verify-code")
    public ResponseEntity<Void> verifyCode(@Valid @RequestBody EmailVerificationRequest request){
        authService.verifyCode(request.email(), request.code());
        return ResponseEntity.ok().build();
    }
}
