package com.swyp.index.application.dto;

import com.swyp.index.domain.User;

import java.util.UUID;

public record LoginResponse(
        UUID userId,
        String email,
        String nickname
) {
    public static LoginResponse from(User user){
        return new LoginResponse(
                user.getUserId(),
                user.getEmail(),
                user.getNickname()
        );
    }
}