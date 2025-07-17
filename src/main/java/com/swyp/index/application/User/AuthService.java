package com.swyp.index.application.User;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.swyp.index.domain.User.User;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.User.UserRepository;
import com.swyp.index.infrastructure.security.JwtProvider;
import com.swyp.index.presentation.dto.LoginRequest;
import com.swyp.index.presentation.dto.LoginResponse;
import com.swyp.index.presentation.dto.SignUpRequest;
import com.swyp.index.presentation.dto.UserInfoResponse;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final UserRepository userRepository;
	private final AuthenticationManager authenticationManager;
	private final JwtProvider jwtTokenProvider;
	private final PasswordEncoder passwordEncoder;
	private final SmtpMailService smtpMailService;
	private final StringRedisTemplate redisTemplate;
	private final TokenService tokenService;

	// Redis 키 접두사 상수를 사용하여 코드의 명확성을 높입니다.
	private static final Duration AUTH_CODE_EXPIRATION = Duration.ofMinutes(5);
	private static final String AUTH_CODE_PREFIX = "AuthCode:";
	private static final String VERIFIED_EMAIL_PREFIX = "Verified:";


	//회원가입을 위한 이메일 인증 코드를 생성하고 발송한다.
	public void sendVerificationCode(String email){
		if(userRepository.existsByEmail(email)){
			throw new CustomException(ErrorCode.USER_NOT_FOUND);
		}
		String authCode = smtpMailService.createAuthCode();
		smtpMailService.sendAuthMail(email, authCode);

		//Redis에 인증 코드 저장
		redisTemplate.opsForValue().set(
			AUTH_CODE_PREFIX + email,
			authCode,
			AUTH_CODE_EXPIRATION
		);
	}

	@Transactional
	//사용자가 입력한 이메일 인증 코드를 검증
	public void verifyEmailAndMarkAsVerified(String email, String code){
		String storedCode = redisTemplate.opsForValue().get(AUTH_CODE_PREFIX + email);

		if(storedCode == null || !storedCode.equals(code)){
			throw new BadCredentialsException("인증코드가 일치하지 않거나 만료되었습니다.");
		}
		// 인증 성공 시, 임시로 '인증됨' 상태를 Redis에 5분간 저장합니다.
		redisTemplate.opsForValue().set(VERIFIED_EMAIL_PREFIX + email, "true", AUTH_CODE_EXPIRATION);

		//인증 성공 시, 재사용을 막기 위해 Redis에서 해당 코드를 즉시 삭제
		redisTemplate.delete(email);
	}

	//이메일 인증을 완료한 사용자의 로컬 회원가입 처리
	@Transactional
	public void signUp(SignUpRequest request){
		// 회원가입 요청 시, Redis에서 해당 이메일이 '인증됨' 상태인지 최종 확인합니다.
		Boolean isVerified = redisTemplate.opsForValue().getOperations().hasKey(VERIFIED_EMAIL_PREFIX + request.email());

		if (isVerified == null || !isVerified) {
			throw new BadCredentialsException("이메일 인증이 완료되지 않았습니다. 다시 인증해주세요.");
		}

		//인증번호 발송 시 이메일 중복을 확인했지만, 그 사이에 다른 사람이 가입했을 수 있으니 한번 더 확인한다.
		if(userRepository.existsByEmail(request.email())){
			// throw new DuplicateEmailException("이미 사용 중인 이메일입니다.");
		}

		if(userRepository.existsByNickname(request.nickname())){
			// throw new DuplicateNicknameException("이미 사용 중인 닉네임입니다.");
		}

		User user = User.ofLocal(
			request.email(),
			passwordEncoder.encode(request.password()),
			request.nickname(),
			"local"
		);

		userRepository.save(user);

		redisTemplate.delete(VERIFIED_EMAIL_PREFIX + request.email());
	}

	//로컬 사용자의 로그인을 처리하고, 토큰과 사용자 정보 반환
	@Transactional
	public Map<String, Object> login(LoginRequest request){
		//AuthenticationManager에게 인증을 위임
		//시큐리티가 내부적으로 UserDetailsService를 통해 사용자를 조회, passwordEncoder로 비밀번호를 비교하는 과정을 모두 처리
		//실패하면 BadCredentialsException이 발생.
		Authentication authentication = authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(request.email(), request.password())
		);
		String email = authentication.getName();
		User user = userRepository.findByEmail(email)
			.orElseThrow(()->new UsernameNotFoundException("인증된 사용자를 DB에서 찾을 수 없습니다."));

		// 토큰 발급 로직을 별도 메서드로 추출하여 재사용성을 높입니다.
		Map<String, String> tokens = issueTokensForUser(user);

		//LoginResponse.from 정적 팩토리 메서드를 사용하여 userId가 포함된 DTO 생성
		LoginResponse userInfo = LoginResponse.from(user);

		Map<String, Object> result = new HashMap<>();
		result.put("tokens", tokens);
		result.put("userInfo", userInfo);
		return result;
	}

	//소셜 로그인 성공 후, 해당 사용자의 이메일로 토큰을 발급
	@Transactional
	public Map<String, String> reissueTokensByEmail(String email) {
		User user = userRepository.findByEmail(email)
			.orElseThrow(() -> new UsernameNotFoundException("소셜 로그인 사용자를 DB에서 찾을 수 없습니다: " + email));
		return issueTokensForUser(user);
	}

	//특정 사용자를 위해 새로운 액세스 토큰과 리프레시 토큰을 발급하고 발급된 리프레시 토큰을 DB에 저장
	private Map<String, String> issueTokensForUser(User user) {
		String newAccessToken = jwtTokenProvider.generateAccessToken(user);
		String newRefreshToken = jwtTokenProvider.generateRefreshToken(user);
		tokenService.refreshAccessToken(newRefreshToken);

		Map<String, String> tokens = new HashMap<>();
		tokens.put("accessToken", newAccessToken);
		tokens.put("refreshToken", newRefreshToken);
		return tokens;
	}

	public UserInfoResponse getCurrentUserInfo(String email) {
		User user = userRepository.findByEmail(email)
			.orElseThrow(() -> new UsernameNotFoundException("해당 이메일의 유저를 찾을 수 없습니다: " + email));


		return new UserInfoResponse(user);
	}
}