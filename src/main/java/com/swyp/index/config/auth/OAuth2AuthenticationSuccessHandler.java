package com.swyp.index.config.auth;


import com.swyp.index.config.JwtUtil;
import com.swyp.index.entity.User;
import com.swyp.index.repository.UserRepository;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.lang.reflect.InaccessibleObjectException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
//소셜 로그인 성공 후 토큰을 생성하고, 클라이언트에게 전달하는 역할을 담당할 클래스
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = extractEmail(oAuth2User);
        log.info("OAuth2 로그인 성공. 이메일: {}", email);

        // 데이터베이스에서 해당 이메일을 사용하는 사용자를 찾습니다.
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 사용자입니다."));

        // JWT 토큰 생성
        String accessToken = jwtUtil.generateAccessToken(user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        //리프레시 토큰을 쿠키에 담기
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); //https 통신에서만 전송
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(refreshTokenCookie);

        //프론트엔드로 리다이렉트할 URL 생성 (토큰을 쿼리 파라미터에 추가)
        // 프론트엔드와 협의하여 이 주소를 결정해야 합니다.
        String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/oauth/redirect")
                .queryParam("accessToken", accessToken)
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);

    }

    private String extractEmail(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // Kakao의 경우
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        if (kakaoAccount != null && kakaoAccount.containsKey("email")) {
            return (String) kakaoAccount.get("email");
        }

        // Naver의 경우
        Map<String, Object> naverResponse = (Map<String, Object>) attributes.get("response");
        if (naverResponse != null && naverResponse.containsKey("email")) {
            return (String) naverResponse.get("email");
        }

        // Google의 경우 (기본 attributes에 바로 포함)
        if (attributes.containsKey("email")) {
            return (String) attributes.get("email");
        }

        throw new IllegalArgumentException("OAuth2 응답에서 이메일을 찾을 수 없습니다.");
    }
}
