package com.swyp.index.presentation.api;
import com.swyp.index.application.dto.LoginRequest;
import com.swyp.index.application.dto.LoginResponse;
import com.swyp.index.application.dto.SignUpRequest;
import com.swyp.index.application.dto.UserInfoResponse;
import com.swyp.index.domain.User;
import com.swyp.index.infrastructure.jwt.JwtTokenProvider;
import com.swyp.index.repository.UserRepository;
import com.swyp.index.application.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

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

    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> getCurrentUser(Principal principal){
        if(principal == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        UserInfoResponse userInfo = authService.getCurrentUserInfo(principal.getName());
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

    @PostMapping("/oauth2/logout")
    public ResponseEntity<?> logout(HttpServletResponse response){
//ACCESS_TOKEN 삭제
        Cookie accessCookie = new Cookie("ACCESS_TOKEN", null);
        accessCookie.setMaxAge(0);
        accessCookie.setPath("/");
        accessCookie.setHttpOnly(true);

//REFRESH_TOKEN 삭제
        Cookie refreshCookie = new Cookie("REFRESH_TOKEN", null);
        refreshCookie.setMaxAge(0);
        refreshCookie.setPath("/");
        refreshCookie.setHttpOnly(true);

//응답에 쿠키 추가(삭제되도록)
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);

        return ResponseEntity.ok("로그아웃 완료!");
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

//Refresh Token 기반으로 Access Token 재발급
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request, HttpServletResponse response){
        String refreshToken = extractCookie(request, "REFRESH_TOKEN");

        if(refreshToken == null || !jwtTokenProvider.validateToken(refreshToken)){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("리프레시 토큰이 유효하지 않습니다.");
        }

        String email = jwtTokenProvider.getEmailFromToken(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("유저가 존재하지 않음"));

        String newAccessToken = jwtTokenProvider.generateAccessToken(email);
        Cookie accessCookie = new Cookie("ACCESS_TOKEN", newAccessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setPath("/");
        response.addCookie(accessCookie);

        return ResponseEntity.ok("새로운 AccessToken 발급 완료!");
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

    private String extractCookie(HttpServletRequest request, String name){
        if(request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}