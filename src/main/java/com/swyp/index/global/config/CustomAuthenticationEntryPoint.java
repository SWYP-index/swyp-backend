package com.swyp.index.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.swyp.index.application.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

//Spring Security에서 인증되지 않은 사용자가 보호된 리소스에 접근하려고 할 때 호출
//호출되는 커스텀 진입점
//api 서버 환경에 맞게 json 형태의 에러 응답을 반환
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    //인증되지 않은 사용자의 접근이 감지되었을 때 실행되는 메서드
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
