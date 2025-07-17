package com.swyp.index.dto;

import com.swyp.index.entity.ProviderType;
import com.swyp.index.entity.User;

public record UserInfoResponse(
        String userId, //외부용 id 추가
        String email,
        String nickname,
        ProviderType provider
) {
    public static UserInfoResponse from(User user){
        return new UserInfoResponse(
                user.getUserId(),
                user.getEmail(),
                user.getNickname(),
                user.getProvider()
        );
    }
}
