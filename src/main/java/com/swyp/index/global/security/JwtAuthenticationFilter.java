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

	// @Override
	// protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
	// 	String uri = request.getRequestURI();
	//
	// 	log.info("요청 URI: {}", uri);
	//
	// 	return uri.startsWith("/api/auth/") ||
	// 		uri.startsWith("/swagger-ui/") ||
	// 		uri.startsWith("/v3/api-docs/") ||
	// 		uri.startsWith("/swagger-resources/") ||
	// 		uri.startsWith("/swagger-ui.html") ||
	// 		uri.startsWith("/webjars/") ||
	// 		uri.startsWith("/error");
	// }
	//
	// @Override
	// protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
	// 	FilterChain filterChain) throws ServletException, IOException {
	// 	String token = jwtProvider.extractToken(request);
	//
	// 	if (token == null || token.isBlank()) {
	// 		throw new BadCredentialsException("토큰이 존재하지 않습니다.");
	// 	}
	//
	// 	if (!jwtProvider.validateToken(token)) {
	// 		throw new BadCredentialsException("유효하지 않은 토큰입니다.");
	// 	}
	//
	// 	log.info("JWT 토큰 검증 성공: {}", token);
	//
	// 	Long userId = Long.valueOf(jwtProvider.getId(token));
	// 	CustomPrincipal principal = new CustomPrincipal(userId);
	//
	// 	UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, null,
	// 		List.of(new SimpleGrantedAuthority("ROLE_USER")));
	//
	// 	SecurityContextHolder.getContext().setAuthentication(authentication);
	//
	// 	log.info("인증 정보 설정 완료: userId={}", principal.id());
	//
	// 	filterChain.doFilter(request, response);
	// }
}
