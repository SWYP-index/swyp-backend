package com.swyp.index.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable=false)
    private String password;
    @Column(nullable = false, length = 50)
    private String name;
    @Column(name = "refresh_token")
    private String refreshToken;

    @Builder
    public User(String email, String password, String name){
        this.email = email;
        this.password = password;
        this.name = name;
    }

    //refresh token을 업데이트하는 메서드
    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }
}
