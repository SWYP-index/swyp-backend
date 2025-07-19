package com.swyp.index.application.user;

import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String userId) {
		User user = userRepository.findById(Long.valueOf(userId))
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		String password = user.getPassword();

		// 소셜 로그인 사용자의 경우 비밀번호가 null일 수 있으므로 빈 문자열로 설정
		if (password == null) {
			password = "";
		}

		return new org.springframework.security.core.userdetails.User(
			String.valueOf(user.getId()),
			password,
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
		);
	}
}