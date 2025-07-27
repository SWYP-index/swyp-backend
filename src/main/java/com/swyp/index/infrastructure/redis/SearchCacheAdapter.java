package com.swyp.index.infrastructure.redis;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

@Repository
public class SearchCacheAdapter {

	private final ValueOperations<String, Object> valueOperations;

	private static final long CACHE_TTL_SECONDS = 24 * 3600; // 24시간

	public SearchCacheAdapter(RedisTemplate<String, Object> redisTemplate) {
		this.valueOperations = redisTemplate.opsForValue();
	}

	// ISBN 리스트용 키 생성 (페이지 포함)
	private String buildIsbnsKey(String title, int page) {
		return "search:isbns:" + title + ":" + page;
	}

	// totalResults용 키 생성 (페이지 제외)
	private String buildTotalResultsKey(String totalResults) {
		return "search:totalResults:" + totalResults;
	}

	// ISBN 리스트 조회
	@SuppressWarnings("unchecked")
	public Optional<List<String>> getIsbnsCache(String title, int page) {
		List<String> cached = (List<String>) valueOperations.get(buildIsbnsKey(title, page));

		return Optional.ofNullable(cached);
	}

	// ISBN 리스트 저장
	public void saveIsbnsCache(String keyword, int page, List<String> isbns) {
		valueOperations.set(buildIsbnsKey(keyword, page), isbns, CACHE_TTL_SECONDS, TimeUnit.SECONDS);
	}

	// totalResults 조회
	public Optional<Integer> getTotalResultsCache(String keyword) {
		Integer totalResults = (Integer) valueOperations.get(buildTotalResultsKey(keyword));

		return Optional.ofNullable(totalResults);
	}

	// totalResults 저장
	public void saveTotalResultsCache(String title, int totalResults) {
		valueOperations.set(buildTotalResultsKey(title), totalResults, CACHE_TTL_SECONDS, TimeUnit.SECONDS);
	}
}
