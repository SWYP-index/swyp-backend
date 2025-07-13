package com.swyp.index.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.swyp.index.entity.User;
import com.swyp.index.jwt.JwtProvider;
import com.swyp.index.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


@Slf4j
//@Service
@RequiredArgsConstructor
public class OAuthService {
    private final ObjectMapper objectMapper;
    private final WebClient webClient;
    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;
    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String kakaoRedirectUri;
    @Value("${spring.security.oauth2.client.provider.kakao.token-uri}")
    private String kakaoTokenUri;

    @Value("${spring.security.oauth2.client.provider.kakao.user-info-uri}")
    private String kakaoUserInfoUri;

    //카카오 로그인 전체 과정을 처리하고, 우리 서비스의 토큰들을 반환
    @Transactional
    public Map<String, String> kakaoLogin(String code){
        //인가 코드로 카카오의 액세스 토큰 받기
        String kakaoAccessToken = getKakaoAccessToken(code);
        //카카오 액세스 토큰으로 카카오 사용자 정보 받기
        JsonNode userInfo = getKakaoUserInfo(kakaoAccessToken);
        //사용자 정보로 우리 DB에서 사용자를 찾거나, 없으면 새로 가입
        User user = registerOrLoginKakaoUser(userInfo);
        //JWT 액세스, 리프레시 토큰 생성
        String accessToken = jwtProvider.generateAccessToken(user.getEmail());
        String refreshToken = jwtProvider.generateRefreshToken(user.getEmail());

        //DB에 새로운 리프레시 토큰을 저장
        user.updateRefreshToken(refreshToken);
        //두 토큰을 Map에 담아 컨트롤러로 반환
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;
    }

    //카카오 서버로부터 액세스 토큰을 받아오는 메서드
    private String getKakaoAccessToken(String code){
        //요청 파라미터 설정
        MultiValueMap<String,String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", kakaoClientId);
        params.add("redirect_uri", kakaoRedirectUri);
        params.add("code",code);

        //HTTP 요청 보내기
        String response = webClient.post()
                .uri(kakaoTokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(params)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        //응답 파싱 후 액세스 토큰 반환
        try{
            return objectMapper.readTree(response).get("access_token").asText();
        }catch(JsonProcessingException e){
            throw new RuntimeException("카카오 액세스 토큰 파싱에 실패했습니다.", e);
        }

    }

    //액세스 토큰을 카카오 서버에 보내 사용자 정보를 받아오는 메서드
    private JsonNode getKakaoUserInfo(String accessToken){
        String response = webClient.get()
                .uri(kakaoUserInfoUri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(String.class)
                .block();
        try{
            return objectMapper.readTree(response);
        }catch(JsonProcessingException e){
            throw new RuntimeException("카카오 사용자 정보 파싱에 실패했습니다.", e);
        }
    }

    //카카오 사용자 정보로 우리 DB의 사용자를 찾거나 새로 생성하는 메서드
    private User registerOrLoginKakaoUser(JsonNode userInfo){
        //카카오로부터 받은 이메일과 닉네임 정보를 추출한다.
        String email = userInfo.get("kakao_account").get("email").asText();
        String nickname = userInfo.get("properties").get("nickname").asText();
        //카카오 사용자의 고유 id를 추출
        String socialId = userInfo.get("id").asText();

        //이메일로 사용자를 찾았을 경우 그 사용자를 반환하고, 찾지 못했을 경우에만 새로운 사용자 생성 및 저장 실행
        return userRepository.findByEmail(email).orElseGet(()->{
            User newUser = User.builder()
                    .email(email)
                    .nickname(nickname)
                    .password(UUID.randomUUID().toString())
                    .provider("KAKAO")
                    .socialId(socialId)
                    .build();
            return userRepository.save(newUser);
        });
    }

}
