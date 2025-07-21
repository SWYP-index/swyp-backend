package com.swyp.index.global.security;

import java.io.CharConversionException;
import java.io.IOException;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;

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
	private final UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		String token = jwtProvider.extractToken(request);

		if (token == null) {
			throw new BadCredentialsException("토큰이 존재하지 않습니다.");
		}

		if (!jwtProvider.validateToken(token)) {
			throw new BadCredentialsException("유효하지 않은 토큰입니다.");
		}

		log.info("JWT 토큰 검증 성공: {}", token);

		UserDetails userDetails = userDetailsService.loadUserByUsername(jwtProvider.getId(token));

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
			null, userDetails.getAuthorities());

		SecurityContextHolder.getContext().setAuthentication(authentication);

		log.info("인증 정보 설정 완료: {}", userDetails.getUsername());

		filterChain.doFilter(request, response);
	}
}
