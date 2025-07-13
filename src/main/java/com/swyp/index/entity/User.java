package com.swyp.index.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EntityListeners(AuditingEntityListener.class)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    //소셜 로그인 시 null이 될 수 있으므로, nullable = true
    @Column
    private String password;

    @Column(nullable = false, unique =true, length = 50)
    private String nickname;
    @Column(name = "social_id", unique = true)
    private String socialId;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(nullable = false, length = 20)
    private String provider;

    @CreatedDate
    @Column(name = "created_at", updatable = false, nullable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    //빌더 패턴은 필요한 필드만 선택적으로 사용할 수 있음.
    @Builder
    public User(String email, String password, String nickname, String provider, String socialId){
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.provider = provider;
        this.socialId = socialId;
    }

    //refresh token을 업데이트하는 메서드
    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }
}
