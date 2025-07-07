package com.swyp.index.service;

import com.swyp.index.dto.LoginRequest;
import com.swyp.index.dto.SignUpRequest;
import com.swyp.index.entity.User;
import com.swyp.index.exception.TokenException;
import com.swyp.index.jwt.JwtProvider;
import com.swyp.index.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @Transactional
    public void signUp(SignUpRequest request){
        if(userRepository.existsByEmail(request.email())){
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .name(request.name())
                .build();
        userRepository.save(user);
    }

    @Transactional
    public Map<String, String> login(LoginRequest request){
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(()->new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        if(!passwordEncoder.matches(request.password(), user.getPassword())){
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        String accessToken = jwtProvider.generateAccessToken(user.getEmail());
        String refreshToken = jwtProvider.generateRefreshToken(user.getEmail());

        user.updateRefreshToken(refreshToken);

        //두 토큰을 Map에 담아 반환
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;

    }
    //토큰 재발급 비즈니스 로직
    @Transactional
    public Map<String, String> reissueTokens(String refreshToken){
        //유효성 검증
        if(!jwtProvider.validateToken(refreshToken)){
            throw new TokenException("유효하지 않은 리프레시 토큰입니다.");
        }
        //토큰에서 사용자 이메일 추출
        String email = jwtProvider.getEmailFromToken(refreshToken);
        // db에서 사용자 찾아서 저장된 리프레시 토큰과 일치하는지 확인
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
}
