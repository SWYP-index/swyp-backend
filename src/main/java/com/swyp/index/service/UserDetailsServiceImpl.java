package com.swyp.index.service;

import com.swyp.index.entity.User;
import com.swyp.index.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

//로그인 과정에서 인증에 필요한 사용자 정보를 데이터베이스에서 가져옴
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException{
        // 1. 이메일로 사용자 정보 조회
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일을 찾을 수 없습니다: " + email));


        String password = user.getPassword();
        // 2. 소셜 로그인 사용자인 경우(비밀번호가 null), 임의의 값을 설정
        if (password == null) {
            password = ""; // 또는 UUID.randomUUID().toString() 등 임의의 값
        }

        // 3. Spring Security의 UserDetails 객체로 변환하여 반환
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                password, // 이제 null이 아님
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")) // 사용자의 권한 설정
        );
    }
}
