package com.swyp.index.global.security;



import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;


public record CustomPrincipal(Long id) implements UserDetails {

	//사용자 권한 관리 기능 추가될 때
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// 현재는 특정 역할을 관리하지 않으므로, 비어있는 리스트를 반환합니다.
		return Collections.emptyList();
	}

	@Override
	public String getPassword() {
		// OAuth2 로그인에서는 비밀번호를 사용하지 않으므로 null을 반환합니다.
		return null;
	}

	@Override
	public String getUsername() {
		// 사용자를 식별할 수 있는 고유한 값이어야 합니다. id가 이 역할에 완벽합니다.
		return String.valueOf(id);
	}

	@Override
	public boolean isAccountNonExpired() {
		// 계정 만료 로직이 없다면 true를 반환합니다.
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// 계정 잠금 로직이 없다면 true를 반환합니다.
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// 자격 증명 만료 로직이 없다면 true를 반환합니다.
		return true;
	}

	//계정 상태 관리 기능이 추가될 때
	@Override
	public boolean isEnabled() {
		// 계정 활성화/비활성화 로직이 없다면 true를 반환합니다.
		return true;
	}

	// --- 사용자가 원래 가지고 있던 추가 메소드 ---
	// 참고: record는 자동으로 public 접근자인 `id()` 메소드를 만들어줍니다.
	// 따라서 이 메소드는 필수는 아니지만, 일관성을 위해 유지할 수 있습니다.
	public Long getId() {
		return id;
	}

}