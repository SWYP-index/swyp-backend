package com.swyp.index.application.User;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.User.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.User.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userRepository.findByEmail(email)
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		String password = user.getPassword();
		// 2. 소셜 로그인 사용자인 경우(비밀번호가 null), 임의의 값을 설정
		if (password == null) {
			password = ""; // 또는 UUID.randomUUID().toString() 등 임의의 값
		}

		return new org.springframework.security.core.userdetails.User(
			user.getEmail(),
			password,
			List.of(new SimpleGrantedAuthority("ROLE_USER"))
		);
	}
}