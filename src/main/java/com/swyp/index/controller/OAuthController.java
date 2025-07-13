package com.swyp.index.controller;

import com.swyp.index.service.OAuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

//@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth/oauth")
public class OAuthController {
    private final OAuthService oAuthService;

    @Value("${jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;
    @Value("${jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @GetMapping("/kakao")
    public ResponseEntity<Void> kakaoLogin(@RequestParam("code") String code, HttpServletResponse httpServletResponse){
        //서비스 계층에 인가 코드를 전달하여 카카오 로그인을 처리하고, 우리 서비스의 토큰들을 받는다.
        Map<String,String> tokens = oAuthService.kakaoLogin(code);

        //응답 헤더에 HttpOnly 쿠키로 토큰들을 추가한다.
        addCookie(httpServletResponse, "accessToken", tokens.get("accessToken"), accessTokenExpirationMs);
        addCookie(httpServletResponse, "refreshToken", tokens.get("refreshToken"), refreshTokenExpirationMs);

        return ResponseEntity.ok().build();
    }

    private void addCookie(HttpServletResponse response, String name, String value, long maxAgeMs){
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .path("/")
                .httpOnly(true)
                .secure(true)//HTTPS 환경에서만 전송
                .maxAge(maxAgeMs/1000)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
