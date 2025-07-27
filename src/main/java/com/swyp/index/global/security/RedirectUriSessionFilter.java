package com.swyp.index.global.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RedirectUriSessionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. OAuth2 인증 요청 경로에만 작동
        if (request.getRequestURI().startsWith("/oauth2/authorization")) {
            // 2. 쿼리 파라미터에서 redirect_uri 읽어오기
            String redirectUri = request.getParameter("redirect_uri");

            // 3. 값이 유효하면 세션에 저장
            if (redirectUri != null && !redirectUri.isBlank()) {
                request.getSession().setAttribute("redirect_uri", redirectUri);
                System.out.println(">> [RedirectUriSessionFilter] Saved redirect_uri to session: " + redirectUri);
            } else {
                System.out.println(">> [RedirectUriSessionFilter] No redirect_uri provided in request.");
            }
        }

        // 4. 다음 필터로 전달
        filterChain.doFilter(request, response);
    }
}