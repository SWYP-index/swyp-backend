package com.swyp.index.config;

import io.jsonwebtoken.security.Password;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                //HttpOnly 쿠키 방식을 사용하므로 CSRF 보호를 비활성화하지 않는다.

        //서버가 상태를 저장하지 않는 STATELESS 방식으로 세션 관리
                .sessionManagement(session->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                //폼 로그인과 HTTP Basic 인증은 사용하지 않음.
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpBasic -> httpBasic.disable())

                //URL 경로별 접근 권한 설정
                .authorizeHttpRequests(auth->auth
                        .requestMatchers("/api/auth/**").permitAll() // '/api/auth/'로 시작하는 모든 경로는 인증 없이 허용
                        .anyRequest().authenticated() // 그 외 모든 요청은 반드시 인증 필요
                )
                //커스텀 필터를 spring security의 인증 필터보다 먼저 검증해야함
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // BCrypt 알고리즘 사용해서 비밀번호 암호화
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
