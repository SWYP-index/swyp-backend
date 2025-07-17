package com.swyp.index.infrastructure.oauth;

import com.swyp.index.domain.ProviderType;
import com.swyp.index.domain.User;
import com.swyp.index.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;
//소셜 로그인 성공 후, 사용자 정보를 처리 클래스
//카카오, 네이버로부터 받은 사용자 정보를 기반으로 우리 서비스의 DB에 사용자를 저장하거나 업데이트
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    //OAuth2 공급자로부터 사용자 정보를 성공적으로 가져왔을 때 호출되는 메서드
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //1. 기본 사용자 정보 불러오기
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);
        log.info("소셜 로그인 제공자로부터 받은 원본 사용자 정보: {}", oAuth2User.getAttributes());

        //2. 어떤 OAuth2 서비스인지 확인
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        if (!"kakao".equals(registrationId)) {
            throw new OAuth2AuthenticationException("카카오 로그인만 지원합니다.");
        }

        //3. 카카오 사용자 정보 꺼내기
        Map<String, Object> attributes = oAuth2User.getAttributes();
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        String nickname = (String) profile.get("nickname");
        String email = (String) kakaoAccount.get("email");

        if (email == null || email.isEmpty()) {
            throw new OAuth2AuthenticationException("이메일을 제공하지 않았습니디.");
        }

        //4. 사용자 DB 조회 or 저장
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .email(email)
                            .nickname(nickname)
                            .provider(ProviderType.KAKAO)
                            .role("USER")
                            .build();
                    return userRepository.save(newUser);
                });
        //5. Spring Security 인증 객체로 변환 후 리턴
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRole().getKey())),
                attributes,
                "id" //attributes에서 사용자 ID로 사용할 키
        );
    }
}
