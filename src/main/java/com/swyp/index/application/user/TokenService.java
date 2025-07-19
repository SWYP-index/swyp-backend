package com.swyp.index.application.user;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.user.UserRepository;
import com.swyp.index.global.security.JwtProvider;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {

	private final JwtProvider jwtProvider;
	private final RedisTemplate<String, String> redisTemplate;
	private final UserRepository userRepository;

	public String reissueAccessToken(String refreshToken) {
		if (!jwtProvider.validateToken(refreshToken)) {
			throw new CustomException(ErrorCode.TOKEN_INVALID);
		}

		String id = jwtProvider.getId(refreshToken);
		String storedRefreshToken = redisTemplate.opsForValue().get(id);

		if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
			throw new CustomException(ErrorCode.TOKEN_EXPIRED);
		}

		User user = userRepository.findById(Long.valueOf(id))
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		return jwtProvider.generateAccessToken(user);
	}
}
