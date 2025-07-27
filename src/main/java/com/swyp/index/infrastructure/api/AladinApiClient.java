package com.swyp.index.infrastructure.api;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AladinApiClient {

	private static final String API_KEY = "ttbleednj01131320001";
	private static final String QUERY_TYPE = "Title";
	private static final String SORT_TYPE = "SalesPoint";
	private static final String OUTPUT_FORMAT = "js";

	private final WebClient webClient;
	private final ObjectMapper objectMapper;

	public AladinSearchResponse searchBooks(String title, int startIndex) {
		String jsonResponse = fetchApiResponse(title, startIndex);

		if (jsonResponse == null || jsonResponse.isBlank()) {
			return AladinSearchResponse.empty();
		}

		return parseResponse(jsonResponse);
	}

	private String fetchApiResponse(String title, int startIndex) {
		return webClient.get()
			.uri(uriBuilder -> uriBuilder
				.queryParam("ttbkey", API_KEY)
				.queryParam("Query", title)
				.queryParam("start", startIndex)
				.queryParam("QueryType", QUERY_TYPE)
				.queryParam("Sort", SORT_TYPE)
				.queryParam("output", OUTPUT_FORMAT)
				.build())
			.retrieve()
			.bodyToMono(String.class)
			.block(); // 동기 호출 (주의 필요)
	}

	private AladinSearchResponse parseResponse(String json) {
		try {
			String fixedJson = json.replace("\\'", "'");
			AladinSearchResponse response = objectMapper.readValue(fixedJson, AladinSearchResponse.class);

			// 페이지 시작 인덱스가 전체 결과 수를 초과하는 경우 빈 응답 반환
			if ((response.startIndex() - 1) * response.itemPerPage() >= response.totalResults()) {
				return AladinSearchResponse.empty();
			}

			return response;
		} catch (JsonProcessingException e) {
			throw new IllegalStateException("Failed to parse JSON from Aladin API", e);
		}
	}
}
