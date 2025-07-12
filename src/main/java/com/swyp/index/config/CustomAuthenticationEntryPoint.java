package com.swyp.index.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.swyp.index.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {
        String errorMessage;
        if("/api/auth/login".equals(request.getRequestURI())){
            errorMessage = "이메일 또는 비밀번호가 일치하지 않습니다.";
        }else{
            errorMessage = "로그인이 필요한 서비스입니다.";
        }
        // 인증 실패에 대한 응답을 직접 구성합니다.
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 상태 코드
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        ErrorResponse errorResponse = new ErrorResponse(errorMessage);
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
