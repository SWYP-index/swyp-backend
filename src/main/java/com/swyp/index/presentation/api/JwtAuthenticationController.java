package com.swyp.index.presentation.api;
import com.swyp.index.domain.User;
import com.swyp.index.infrastructure.jwt.JwtTokenProvider;
import com.swyp.index.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class JwtAuthenticationController {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    // 1. 로그인한 사용자 정보 확인
    @GetMapping("/jwt-me")
    public String getMyEmail(HttpServletRequest request) {
        String token = extractTokenFromCookie(request, "ACCESS_TOKEN");

        if (token == null || !jwtTokenProvider.validateToken(token)) {
            return "유효하지 않은 토큰입니다.";
        }

        String email = jwtTokenProvider.getEmailFromToken(token);
        return "로그인된 사용자 이메일: " + email;
    }

    private String extractTokenFromCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null) return null;

        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(name)) {
                return cookie.getValue();
            }
        }
        return null;
    }

    //Refresh 토큰으로 새로운 Access 토큰 발급
    @GetMapping("/refresh")
    public String refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = extractTokenFromCookie(request, "REFRESH_TOKEN");

        if (refreshToken == null || !jwtTokenProvider.validateToken(refreshToken)) {
            return "유효하지 않은 리프레시 토큰입니다.";
        }

        String email = jwtTokenProvider.getEmailFromToken(refreshToken);
        //DB에서 유저 확인
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("유저가 존재하지 않음"));
        String newAccessToken = jwtTokenProvider.generateAccessToken(email);

        Cookie accessCookie = new Cookie("ACCESS_TOKEN", newAccessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setPath("/");
        response.addCookie(accessCookie);

        return "새로운 AccessToken 발급 완료!";
    }
}
//    // 쿠키 추출 도우미
//    private String extreactTokenFromCookie(HttpServletRequest request, String name){
//        if(request.getCookies() == null) return null;
//
//        for(Cookie cookie : request.getCookies()){
//            if(cookie.getName().equals(name)){
//                return cookie.getValue();
//            }
//        }
//        return null;
//    }
