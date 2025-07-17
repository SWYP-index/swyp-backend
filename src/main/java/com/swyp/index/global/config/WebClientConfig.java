package com.swyp.index.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

//외부 API 서버와 비동기 HTTP 통신을 하기 위한 WebClient를 설정하고 빈으로 등록
@Configuration
public class WebClientConfig {
    @Bean
    public WebClient webClient(){
        return WebClient.builder().build();
    }
}
