package com.swyp.index.global.config;



import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {
    private static final String SECURITY_SCHEME = "JWT Authentication";
    @Bean
    public OpenAPI openAPI() {
        //API 문서의 기본 정보 설정
        Info info = new Info()
                .title("Index 프로젝트 API 문서")
                .version("v1.0.0")
                .description("INDEX 프로젝트의 API 명세서입니다.");

        //인증 스키마 설정
        Components compnents = new Components()
                .addSecuritySchemes(SECURITY_SCHEME, new SecurityScheme()
                        .name(SECURITY_SCHEME)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT"));
        //서버 정보 설정
        Server server = new Server().url("http://localhost:8080").description("로컬 개발 서버");

        return new OpenAPI()
                .info(info)
                .servers(List.of(server))
                .components(compnents);

    }

}
