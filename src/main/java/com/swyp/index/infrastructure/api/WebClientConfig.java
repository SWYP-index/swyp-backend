package com.swyp.index.infrastructure.api;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

	@Bean
	public WebClient aladinWebClient() {
		return WebClient.builder()
			.baseUrl("http://www.aladin.co.kr/ttb/api/ItemSearch.aspx")
			.build();
	}
}
