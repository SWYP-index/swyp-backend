package com.swyp.index.service;

import com.swyp.index.dto.LoginRequest;
import com.swyp.index.dto.LoginResponse;
import com.swyp.index.dto.SignUpRequest;
import com.swyp.index.entity.User;
import com.swyp.index.exception.DuplicateEmailException;
import com.swyp.index.exception.DuplicateNicknameException;
import com.swyp.index.exception.TokenException;
import com.swyp.index.jwt.JwtProvider;
import com.swyp.index.repository.UserRepository;
import lombok.RequiredArgsConstructor;
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

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;

    private final MailService mailService;
    private final StringRedisTemplate redisTemplate;

    //인증 코드 유효 시간 (5분)
    private static final Duration AUTH_CODE_EXPIRATION = Duration.ofMinutes(5);

    //인증 코드를 생성하고 이메일로 발송한 뒤, redis에 저장한다.
    public void sendVerificationCode(String email){
        if(userRepository.existsByEmail(email)){
            throw new DuplicateEmailException("이미 사용 중인 이메일입니다.");
        }
        String authCode = mailService.createAuthCode();
        mailService.sendAuthMail(email, authCode);

        //Redis에 인증 코드 저장
        redisTemplate.opsForValue().set(
                email,
                authCode,
                AUTH_CODE_EXPIRATION
        );
    }

    //사용자가 입력한 인증 코드가 올바른지 Redis에서 확인
    public void verifyCode(String email, String code){
        String storedCode = redisTemplate.opsForValue().get(email);

        if(storedCode == null || !storedCode.equals(code)){
            throw new BadCredentialsException("인증코드가 일치하지 않거나 만료되었습니다.");
        }

        //인증 성공 시, 재사용을 막기 위해 Redis에서 해당 코드를 즉시 삭제
        redisTemplate.delete(email);
    }

    @Transactional
    public void signUp(SignUpRequest request){
        //회원가입 요청 시, 먼저 인증 코드가 올바른지 검증
        verifyCode(request.email(), request.authCode());

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
                .build();
        userRepository.save(user);
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


        String accessToken = jwtProvider.generateAccessToken(email);
        String refreshToken = jwtProvider.generateRefreshToken(email);

        user.updateRefreshToken(refreshToken);

        //컨트롤러에 전달할 사용자 정보와 토큰들을 Map에 담아 반환한다.
        LoginResponse userInfo = new LoginResponse(user.getEmail(), user.getNickname());
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        Map<String, Object> result = new HashMap<>();
        result.put("tokens", tokens);
        result.put("userInfo", userInfo);

        return result;
    }
    //토큰 재발급 비즈니스 로직
    @Transactional
    public Map<String, String> reissueTokens(String refreshToken){
        //토큰 자체 유효성 검증
        if(!jwtProvider.validateToken(refreshToken)){
            throw new TokenException("유효하지 않은 리프레시 토큰입니다.");
        }
        //토큰에서 사용자 이메일 추출
        // db에서 사용자 찾아서 저장된 리프레시 토큰과 일치하는지 확인
        String email = jwtProvider.getEmailFromToken(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(()-> new TokenException("사용자를 찾을 수 없습니다."));

        if(!refreshToken.equals(user.getRefreshToken())){
            throw new TokenException("토큰이 일치하지 않습니다.");
        }
        //검증 통과한 후, 새로운 토큰 생성
        String newAccessToken = jwtProvider.generateAccessToken(email);
        String newRefreshToken = jwtProvider.generateRefreshToken(email);

        //db에 새로운 리프레시 토큰 저장
        user.updateRefreshToken(newRefreshToken);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", newAccessToken);
        tokens.put("refreshToken", newRefreshToken);

        return tokens;
    }

    @Transactional
    public void logout(String email){
        User user = userRepository.findByEmail(email)
                .orElseThrow(()-> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        user.updateRefreshToken(null);
    }
}
