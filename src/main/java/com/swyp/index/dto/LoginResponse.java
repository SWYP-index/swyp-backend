package com.swyp.index.dto;

import com.swyp.index.entity.User;

public record LoginResponse(
        String userId,
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