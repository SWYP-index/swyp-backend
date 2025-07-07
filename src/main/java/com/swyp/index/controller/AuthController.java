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
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
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

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Principal principal, HttpServletResponse response){

        authService.logout(principal.getName());
        //클라이언트의 브라우저에서 토큰 쿠키 삭제
        expireCookie(response, "accessToken");
        expireCookie(response, "refreshToken");

        return ResponseEntity.ok().build();
    }

    //토큰 재발급 처리
    @PostMapping("/reissue")
    public ResponseEntity<Void> reissue(
            @CookieValue("refreshToken") String refreshToken,
            HttpServletResponse response
    ){
        Map<String, String> newTokens = authService.reissueTokens(refreshToken);

        addCookie(response, "accessToken", newTokens.get("accessToken"), accessTokenExpirationMs);
        addCookie(response, "refreshToken", newTokens.get("refreshToken"), refreshTokenExpirationMs);

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

    //쿠키 만료시키는 메서드
    private void expireCookie(HttpServletResponse response, String name){
        ResponseCookie cookie = ResponseCookie.from(name, "")
                .path("/")
                .httpOnly(true)
                .secure(true)
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
