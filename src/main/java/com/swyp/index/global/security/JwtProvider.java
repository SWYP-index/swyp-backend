package com.swyp.index.global.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtProvider {
	@Value("${jwt.secret}")
	private String secretKey;

	@Value("${jwt.access-token-expiration}")
	private long accessTokenExpiration;

	@Value("${jwt.refresh-token-expiration}")
	private long refreshTokenExpiration;

	private Key getSigningKey() {
		return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	}

	public String generateAccessToken(Long userId) {
		return Jwts.builder()
			.setSubject(String.valueOf(userId))
			.setIssuedAt(new Date())
			.setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
			.signWith(getSigningKey(), SignatureAlgorithm.HS256)
			.compact();
	}

	public String generateRefreshToken(Long userId) {
		return Jwts.builder()
			.setSubject(String.valueOf(userId))
			.setIssuedAt(new Date())
			.setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
			.signWith(getSigningKey(), SignatureAlgorithm.HS256)
			.compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(getSigningKey())
				.build()
				.parseClaimsJws(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}

	public String extractToken(HttpServletRequest request) {
		String auth = request.getHeader("Authorization");

		if (auth != null && auth.startsWith("Bearer ")) {
			return auth.substring(7);
		}

		return null;
	}

	public String getId(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(getSigningKey())
			.build()
			.parseClaimsJws(token)
			.getBody()
			.getSubject();
	}
}
