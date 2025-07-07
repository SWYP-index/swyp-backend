package com.swyp.index.config;

import com.swyp.index.jwt.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//모든 api 요청에 대해 jwt 토큰을 검사하여 인증을 처리하는 필터
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtProvider jwtProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        //요청의 쿠키에서 accessToken을 찾아 토큰 추출
        String token = resolveTokenFromCookie(request);

        if(StringUtils.hasText(token) && jwtProvider.validateToken(token)){
            String email = jwtProvider.getEmailFromToken(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                  userDetails, null, userDetails.getAuthorities()
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            //SecurityContext에 인증 정보를 저장하여, 해당 요청 동안 사용자가 인증된 상태임을 유지
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    // 요청의 쿠키 배열에서 accessToken이라는 이름의 쿠키를 찾아 그 값을 반환해주는 메서드
    private String resolveTokenFromCookie(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies == null){
            return null;
        }
        for(Cookie cookie : cookies){
            if("accessToken".equals(cookie.getName())){
                return cookie.getValue();
            }
        }
        return null;
    }

}
