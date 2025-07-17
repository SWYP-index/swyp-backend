package com.swyp.index.config;

import com.swyp.index.jwt.JwtTokenProvider;
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

//모든 api 요청에 대해 jwt 액세스 토큰을 검사하여 인증을 처리하는 필터
//spring security의 기본 필터 체인에 추가되어 컨트롤러에 도달하기 전에 실행된다.
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        //요청의 쿠키에서 accessToken을 찾아 토큰 추출
        String token = resolveTokenFromCookie(request);

        //토큰이 존재하고 jwtProvider를 통해 검사했을 때 유효성 검사 통과했다면
        if(StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)){
            //토큰에서 사용자 이메일 추출.
            String email = jwtTokenProvider.getEmailFromToken(token);
            //이메일을 사용하여 데이터베이스에서 전체 사용자 정보를 조회
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            //조회된 사용자 정보를 기반으로 인증 객체를 생성. 이 객체는 spring security가 현재 사용자를 식별하는 데 사용.
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
            );

            //요청에 대한 세부 정보를 인증 객체에 설정
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // securityContextHolder에 인증 객체를 저장. 해당 요청 동안 사용자는 인증된 상태가 됨.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 다음 필터로 요청을 그대로 전달
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