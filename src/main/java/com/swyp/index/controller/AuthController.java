package com.swyp.index.controller;

import com.swyp.index.dto.LoginRequest;
import com.swyp.index.dto.LoginResponse;
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
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response
    ){
        //서비스에서 로그인 처리 후 토큰과 사용자 정보를 모두 받아옴.
        Map<String, Object> result = authService.login(request);
        Map<String, String> tokens = (Map<String, String>) result.get("tokens");
        LoginResponse userInfo = (LoginResponse) result.get("userInfo");

        //토큰을 쿠키에 설정한다.
        addCookie(response, "accessToken", tokens.get("accessToken"), accessTokenExpirationMs);
        addCookie(response, "refreshToken", tokens.get("refreshToken"), refreshTokenExpirationMs);

        return ResponseEntity.ok(userInfo);
    }

    //@param principal: 스프링 시큐리티가 현재 인증된 사용자의 정보를 담아주는 객체
    //JwtAuthenticationFilter에서 인증 정보를 securitycontext에 저장했기 때문에 여기서 사용함.
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
    private void addCookie(HttpServletResponse response, String nickname, String value, long maxAgeMs){
        ResponseCookie cookie = ResponseCookie.from(nickname, value)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .maxAge(maxAgeMs/1000)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    //쿠키 만료시키는 메서드
    private void expireCookie(HttpServletResponse response, String nickname){
        ResponseCookie cookie = ResponseCookie.from(nickname, "")
                .path("/")
                .httpOnly(true)
                .secure(true)
                .maxAge(0)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
