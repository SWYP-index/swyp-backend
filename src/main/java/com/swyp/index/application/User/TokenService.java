package com.swyp.index.application.User;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.User.User;
import com.swyp.index.infrastructure.User.UserRepository;
import com.swyp.index.infrastructure.security.JwtProvider;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {

	private final JwtProvider jwtProvider;
	private final RedisTemplate<String, String> redisTemplate;
	private final UserRepository userRepository;

	public String refreshAccessToken(String refreshToken) {
		if (!jwtProvider.validateToken(refreshToken)) {
			throw new RuntimeException("Invalid refresh token");
		}

		String email = jwtProvider.getEmail(refreshToken);
		String storedRefreshToken = redisTemplate.opsForValue().get(email);

		if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
			throw new RuntimeException("Refresh token mismatch");
		}

		User user = userRepository.findByEmail(email)
			.orElseThrow(() -> new RuntimeException("User not found"));

		return jwtProvider.generateAccessToken(user);
	}

	public void deleteRefreshToken(String refreshToken) {
		if (!jwtProvider.validateToken(refreshToken)) {
			return;
		}

		String email = jwtProvider.getEmail(refreshToken);
		String storedRefreshToken = redisTemplate.opsForValue().get(email);

		if (storedRefreshToken != null && storedRefreshToken.equals(refreshToken)) {
			redisTemplate.delete(email);
		}
	}

	public boolean exists(String refreshToken) {
		if (!jwtProvider.validateToken(refreshToken)) {
			return false;
		}

		String email = jwtProvider.getEmail(refreshToken);
		String storedRefreshToken = redisTemplate.opsForValue().get(email);

		return storedRefreshToken != null && storedRefreshToken.equals(refreshToken);
	}
}
