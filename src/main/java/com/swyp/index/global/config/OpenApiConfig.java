package com.swyp.index.global.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;

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
        Components components = new Components()
                .addSecuritySchemes(SECURITY_SCHEME, new SecurityScheme()
                        .name(SECURITY_SCHEME)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT"));

        //서버 정보 설정
        Server prodServer = new Server().url("https://api-index.store").description("인덱스 API 서버");
        Server localServer = new Server().url("http://localhost:8080").description("로컬 개발 서버");

        return new OpenAPI()
                .info(info)
                .servers(List.of(prodServer, localServer))
                .components(components);
    }
}
