package com.swyp.index.presentation.dto.user;

import com.swyp.index.domain.user.Provider;
import com.swyp.index.domain.user.User;

/**
 * 로그인 성공 후 또는 사용자 정보 조회 시
 * 클라이언트에게 반환할 데이터를 담는 DTO 입니다.
 */
public record UserInfoResponse(
	Long userId,
	String email,
	String nickname,
	Provider provider
) {
	/**
	 * User 엔티티 객체를 UserInfoResponse DTO로 변환하는 추가 생성자입니다.
	 * @param user User 엔티티 객체
	 */
	public UserInfoResponse(User user) {
		// this()를 호출하여 record의 기본 생성자에 값을 전달합니다.
		this(
			user.getId(),
			user.getEmail(),
			user.getNickname(),
			user.getProvider()
		);
	}
}