package com.swyp.index.application.user;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.swyp.index.domain.user.Provider;
import com.swyp.index.domain.user.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.global.security.JwtProvider;
import com.swyp.index.infrastructure.user.UserRepository;
import com.swyp.index.presentation.dto.user.LoginRequest;
import com.swyp.index.presentation.dto.user.SignUpRequest;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {
	private final UserRepository userRepository;
	private final AuthenticationManager authenticationManager;
	private final JwtProvider jwtProvider;
	private final PasswordEncoder passwordEncoder;
	private final SmtpMailService smtpMailService;
	private final StringRedisTemplate redisTemplate;

	// Redis 키 접두사 상수를 사용하여 코드의 명확성을 높입니다.
	private static final Duration AUTH_CODE_EXPIRATION = Duration.ofMinutes(5);
	private static final String AUTH_CODE_PREFIX = "AuthCode:";
	private static final String VERIFIED_EMAIL_PREFIX = "Verified:";

	// 회원가입을 위한 이메일 인증 코드를 생성하고 발송한다.
	public void sendVerificationCode(String email) {
		if (userRepository.existsByEmailAndProvider(email, Provider.LOCAL)) {
			throw new CustomException(ErrorCode.DUPLICATE_EMAIL);
		}

		String authCode = smtpMailService.createAuthCode();
		smtpMailService.sendAuthMail(email, authCode);

		// Redis에 인증 코드 저장
		redisTemplate.opsForValue().set(
			AUTH_CODE_PREFIX + email,
			authCode,
			AUTH_CODE_EXPIRATION
		);
	}

	// 사용자가 입력한 이메일 인증 코드를 검증
	public void verifyEmailAndMarkAsVerified(String email, String authCode) {
		String storedCode = redisTemplate.opsForValue().get(AUTH_CODE_PREFIX + email);

		if (storedCode == null || !storedCode.equals(authCode)) {
			throw new BadCredentialsException("인증코드가 일치하지 않거나 만료되었습니다.");
		}
		// 인증 성공 시, 임시로 '인증됨' 상태를 Redis에 5분간 저장합니다.
		redisTemplate.opsForValue().set(VERIFIED_EMAIL_PREFIX + email, "true", AUTH_CODE_EXPIRATION);

		//인증 성공 시, 재사용을 막기 위해 Redis에서 해당 코드를 즉시 삭제
		redisTemplate.delete(email);
	}

	// 이메일 인증을 완료한 사용자의 로컬 회원가입 처리
	public void signUp(SignUpRequest request) {
		// 회원가입 요청 시, Redis에서 해당 이메일이 '인증됨' 상태인지 최종 확인합니다.
		Boolean isVerified = redisTemplate.opsForValue()
			.getOperations()
			.hasKey(VERIFIED_EMAIL_PREFIX + request.email());

		if (isVerified == null || !isVerified) {
			throw new BadCredentialsException("이메일 인증이 완료되지 않았습니다. 다시 인증해주세요.");
		}

		// 인증번호 발송 시 이메일 중복을 확인했지만, 그 사이에 다른 사람이 가입했을 수 있으니 한번 더 확인한다.
		if (userRepository.existsByEmailAndProvider(request.email(), Provider.LOCAL)) {
			throw new CustomException(ErrorCode.DUPLICATE_EMAIL);
		}

		if (userRepository.existsByNickname(request.nickname())) {
			throw new CustomException(ErrorCode.DUPLICATE_NICKNAME);
		}

		User user = User.ofLocal(
			request.email(),
			request.nickname(),
			passwordEncoder.encode(request.password()),
			"local"
		);

		userRepository.save(user);

		redisTemplate.delete(VERIFIED_EMAIL_PREFIX + request.email());
		redisTemplate.delete(AUTH_CODE_PREFIX + request.email());
	}

	// 로컬 사용자의 로그인을 처리하고, 토큰과 사용자 정보 반환
	public User login(LoginRequest request) {
		// AuthenticationManager에게 인증을 위임
		// 시큐리티가 내부적으로 UserDetailsService를 통해 사용자를 조회, passwordEncoder로 비밀번호를 비교하는 과정을 모두 처리
		// 실패하면 BadCredentialsException이 발생.
		Authentication authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(request.email(), request.password())
		);

		String email = authentication.getName();

		return userRepository.findByEmailAndProvider(email, Provider.LOCAL)
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));
	}
}