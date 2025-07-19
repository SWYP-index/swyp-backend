package com.swyp.index.presentation.api.user;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.user.UserRepository;
import com.swyp.index.presentation.dto.user.user.UserResponse;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserApi {

	private final UserRepository userRepository;

	@GetMapping("/me")
	public ResponseEntity<?> getUser(Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			throw new CustomException(ErrorCode.UNAUTHORIZED);
		}

		Object principal = authentication.getPrincipal();

		if (!(principal instanceof UserDetails userDetails)) {
			throw new CustomException(ErrorCode.UNAUTHORIZED);
		}

		User user = userRepository.findById(Long.valueOf(userDetails.getUsername()))
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		return ResponseEntity.ok(UserResponse.from(user));
	}
}