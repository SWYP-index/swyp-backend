package com.swyp.index.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                //테스트할때만 csrf 보호기능 비활성화/ 나중에 주석처리하자.
                .csrf(AbstractHttpConfigurer::disable)
                //폼 로그인과 HTTP Basic 인증은 사용하지 않음.
                .formLogin(formLogin -> formLogin.disable())
                .httpBasic(httpBasic -> httpBasic.disable())

                //서버가 상태를 저장하지 않는 STATELESS 방식으로 세션 관리
                .sessionManagement(session->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                //인증 실패 예외 발생 시, 우리가 만든 로직을 따르도록 설정
                .exceptionHandling(exception->
                        exception.authenticationEntryPoint(customAuthenticationEntryPoint))
                //URL 경로별 접근 권한 설정
                .authorizeHttpRequests(auth->auth
                        .requestMatchers("/api/auth/**").permitAll() // '/api/auth/'로 시작하는 모든 경로는 인증 없이 허용
                        .anyRequest().authenticated() // 그 외 모든 요청은 반드시 인증 필요
                )
                //커스텀 필터를 spring security의 기본 인증 필터보다 먼저 검증해야함
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    // BCrypt 알고리즘 사용해서 비밀번호 암호화
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
