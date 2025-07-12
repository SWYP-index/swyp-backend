package com.swyp.index.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j // 클래스에 로그를 찍을 수 있는 기능을 자동으로 추가해줌.
@Component
public class JwtProvider {
    private final SecretKey secretKey;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration-ms}") long accessTokenExpirationMs,
            @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenExpirationMs
    ){
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    //액세스 토큰 생성
    public String generateAccessToken(String email){
        return generateToken(email, accessTokenExpirationMs);
    }

    //리프레시 토큰 생성
    public String generateRefreshToken(String email){
        return generateToken(email, refreshTokenExpirationMs);
    }

    //토큰 생성 로직
    private String generateToken(String email, long expirationMs){
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact(); //토큰 생성 및 직렬화
    }

    //토큰 유효성 검증
    public boolean validateToken(String token){
        try{
            getClaims(token);
            return true;
        } catch(Exception e){
            log.error("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    //토큰에서 사용자 이메일 정보 추출
    public String getEmailFromToken(String token){
        return getClaims(token).getSubject();
    }

    //토큰을 파싱하여 페이로드 정보를 반환하는 메서드
    private Claims getClaims(String token){
        return Jwts.parser()
                .verifyWith(secretKey) // 제공된 비밀키로 서명 검증
                .build()
                .parseSignedClaims(token)// 서명된 토큰을 파싱
                .getPayload();
    }
}
