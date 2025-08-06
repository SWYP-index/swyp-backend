package com.swyp.index.application.user;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.UserRepository;
import com.swyp.index.global.security.JwtProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

	private final JwtProvider jwtProvider;
	private final RedisTemplate<String, String> redisTemplate;
	private final UserRepository userRepository;

	public void validateRefreshToken(String refreshToken) {
		jwtProvider.validateToken(refreshToken);

		String id = jwtProvider.getId(refreshToken);
		String storedRefreshToken = redisTemplate.opsForValue().get(id);

		log.info("user id: {}, refresh token: {}", id, refreshToken);
		log.info("stored refresh token: {}", storedRefreshToken);

		if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
			throw new CustomException(ErrorCode.INVALID_REFRESH_TOKEN);
		}
	}

	public String reissueAccessToken(String refreshToken) {
		String id = jwtProvider.getId(refreshToken);
		User user = userRepository.findById(Long.valueOf(id))
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		return jwtProvider.generateAccessToken(user.getId());
	}

	public void saveRefreshToken(User user, String refreshToken) {
		String key = "refreshToken:" + user.getId();

		redisTemplate.opsForValue().set(key, refreshToken, Duration.ofDays(7));
	}

	public void deleteRefreshToken(User user) {
		String key = "refreshToken:" + user.getId();

		redisTemplate.delete(key);
	}

	public void addAccessTokenToBlacklist(String accessToken) {
		String key = "blacklist:" + accessToken;

		redisTemplate.opsForValue().set(key, "logout", Duration.ofMinutes(15));
	}

	public boolean isAccessTokenBlacklisted(String accessToken) {
		String key = "blacklist:" + accessToken;

		return redisTemplate.hasKey(key);
	}
}
