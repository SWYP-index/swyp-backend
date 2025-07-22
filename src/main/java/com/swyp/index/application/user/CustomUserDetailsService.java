package com.swyp.index.application.user;

import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.user.Provider;
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
	public UserDetails loadUserByUsername(String email) {
		User user = userRepository.findByEmailAndProvider(email, Provider.LOCAL)
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		return new org.springframework.security.core.userdetails.User(
			String.valueOf(user.getId()),
			user.getPassword(),
			Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
		);
	}
}