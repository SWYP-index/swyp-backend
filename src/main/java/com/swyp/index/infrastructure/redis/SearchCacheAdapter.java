package com.swyp.index.infrastructure.redis;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.swyp.index.infrastructure.api.AladinSearchResponse;

@Repository
public class SearchCacheAdapter {
	private static final long CACHE_TTL_SECONDS = 24 * 3600; // 24시간

	private final ValueOperations<String, Object> valueOperations;


	public SearchCacheAdapter(RedisTemplate<String, Object> redisTemplate) {
		this.valueOperations = redisTemplate.opsForValue();
	}

	public void saveCache(AladinSearchResponse response, List<String> isbns) {
		saveIsbnsCache(response.title(), response.startIndex(), isbns);

		saveTotalResultsCache(response.title(), response.totalResults());
	}

	@SuppressWarnings("unchecked")
	public Optional<List<String>> getIsbnsCache(String title, int page) {
		List<String> cached = (List<String>) valueOperations.get(buildIsbnsKey(title, page));

		return Optional.ofNullable(cached);
	}

	public void saveIsbnsCache(String keyword, int page, List<String> isbns) {
		valueOperations.set(buildIsbnsKey(keyword, page), isbns, CACHE_TTL_SECONDS, TimeUnit.SECONDS);
	}

	public Optional<Integer> getTotalResultsCache(String keyword) {
		Integer totalResults = (Integer) valueOperations.get(buildTotalResultsKey(keyword));

		return Optional.ofNullable(totalResults);
	}

	public void saveTotalResultsCache(String title, int totalResults) {
		valueOperations.set(buildTotalResultsKey(title), totalResults, CACHE_TTL_SECONDS, TimeUnit.SECONDS);
	}

	private String buildIsbnsKey(String title, int page) {
		return "search:isbns:" + title + ":" + page;
	}

	private String buildTotalResultsKey(String totalResults) {
		return "search:totalResults:" + totalResults;
	}
}
