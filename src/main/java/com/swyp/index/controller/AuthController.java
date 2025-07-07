package com.swyp.index.controller;

import com.swyp.index.dto.LoginRequest;
import com.swyp.index.dto.SignUpRequest;
import com.swyp.index.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @Value("${jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;

    @Value("${jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @PostMapping("/signup")
    public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequest request){
        authService.signUp(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response
    ){
        Map<String, String> tokens = authService.login(request);
        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        //각각의 토큰을 HttpOnly 쿠키로 만들어 응답에 추가
        addCookie(response, "accessToken", accessToken, accessTokenExpirationMs);
        addCookie(response, "refreshToken", refreshToken, refreshTokenExpirationMs);

        return ResponseEntity.ok().build();
    }

    //쿠키를 생성하고 응답에 추가하는 메서드
    private void addCookie(HttpServletResponse response, String name, String value, long maxAgeMs){
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .maxAge(maxAgeMs/1000)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

}
