package com.swyp.index.global.security;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtProvider jwtProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		String token = jwtProvider.extractToken(request);

		if (token != null && !token.isBlank() && jwtProvider.validateToken(token)) {
			Long userId = Long.valueOf(jwtProvider.getId(token));
			CustomPrincipal principal = new CustomPrincipal(userId);

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, null,
				List.of(new SimpleGrantedAuthority("ROLE_USER")));

			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		// 인증 정보가 없으면 AuthenticationEntryPoint를 통해 401 Unauthorized 응답을 반환합니다.
		filterChain.doFilter(request, response);
	}
}
