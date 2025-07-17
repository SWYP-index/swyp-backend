package com.swyp.index.service;

import com.swyp.index.dto.LoginRequest;
import com.swyp.index.dto.LoginResponse;
import com.swyp.index.dto.SignUpRequest;
import com.swyp.index.dto.UserInfoResponse;
import com.swyp.index.entity.ProviderType;
import com.swyp.index.entity.User;
import com.swyp.index.exception.DuplicateEmailException;
import com.swyp.index.exception.DuplicateNicknameException;
import com.swyp.index.exception.TokenException;
import com.swyp.index.jwt.JwtTokenProvider;
import com.swyp.index.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final StringRedisTemplate redisTemplate;

    // Redis 키 접두사 상수를 사용하여 코드의 명확성을 높입니다.
    private static final Duration AUTH_CODE_EXPIRATION = Duration.ofMinutes(5);
    private static final String AUTH_CODE_PREFIX = "AuthCode:";
    private static final String VERIFIED_EMAIL_PREFIX = "Verified:";


    //인증 코드를 생성하고 이메일로 발송한 뒤, redis에 저장한다.
    public void sendVerificationCode(String email){
        if(userRepository.existsByEmail(email)){
            throw new DuplicateEmailException("이미 사용 중인 이메일입니다.");
        }
        String authCode = mailService.createAuthCode();
        mailService.sendAuthMail(email, authCode);

        //Redis에 인증 코드 저장
        redisTemplate.opsForValue().set(
                AUTH_CODE_PREFIX + email,
                authCode,
                AUTH_CODE_EXPIRATION
        );
    }

    @Transactional
    //사용자가 입력한 인증 코드가 올바른지 Redis에서 확인
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

    @Transactional
    public void signUp(SignUpRequest request){
        // 회원가입 요청 시, Redis에서 해당 이메일이 '인증됨' 상태인지 최종 확인합니다.
        Boolean isVerified = redisTemplate.opsForValue().getOperations().hasKey(VERIFIED_EMAIL_PREFIX + request.email());

        if (isVerified == null || !isVerified) {
            throw new BadCredentialsException("이메일 인증이 완료되지 않았습니다. 다시 인증해주세요.");
        }

        //인증번호 발송 시 이메일 중복을 확인했지만, 그 사이에 다른 사람이 가입했을 수 있으니 한번 더 확인한다.
        if(userRepository.existsByEmail(request.email())){
            throw new DuplicateEmailException("이미 사용 중인 이메일입니다.");
        }

        if(userRepository.existsByNickname(request.nickname())){
            throw new DuplicateNicknameException("이미 사용 중인 닉네임입니다.");
        }
        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .nickname(request.nickname())
                .provider(ProviderType.LOCAL)
                .build();
        userRepository.save(user);

        redisTemplate.delete(VERIFIED_EMAIL_PREFIX + request.email());
    }

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
    //토큰 재발급 비즈니스 로직
    @Transactional
    public Map<String, String> reissueTokens(String refreshToken){
        //토큰 자체 유효성 검증
        if(!jwtTokenProvider.validateToken(refreshToken)){
            throw new TokenException("유효하지 않은 리프레시 토큰입니다.");
        }
        String email = jwtTokenProvider.getEmailFromToken(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(()-> new TokenException("사용자를 찾을 수 없습니다."));

        if (!Objects.equals(refreshToken, user.getRefreshToken())) {
            throw new TokenException("토큰이 일치하지 않습니다.");
        }

        return issueTokensForUser(user);
    }

    /**
     * ◀◀◀ [추가된 메서드] 소셜 로그인 성공 후 JwtSuccessHandler에서 호출됩니다.
     * 이메일을 기반으로 사용자를 찾아 토큰을 발급합니다.
     */
    @Transactional
    public Map<String, String> reissueTokensByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("소셜 로그인 사용자를 DB에서 찾을 수 없습니다: " + email));
        return issueTokensForUser(user);
    }

    @Transactional
    public void logout(String email){
        User user = userRepository.findByEmail(email)
                .orElseThrow(()-> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        user.updateRefreshToken(null);
    }
    @Transactional(readOnly = true)
    public UserInfoResponse getCurrentUserInfo(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일의 유저를 찾을 수 없습니다: " + email));

        // ◀◀ [수정] UserInfoResponse.from 정적 팩토리 메서드를 사용하여 userId가 포함된 DTO 생성
        return UserInfoResponse.from(user);
    }
    //토큰 발급 로직을 공통 메서드로 추출
    private Map<String, String> issueTokensForUser(User user) {
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getEmail());
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail());
        user.updateRefreshToken(newRefreshToken);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", newAccessToken);
        tokens.put("refreshToken", newRefreshToken);
        return tokens;
    }

}
