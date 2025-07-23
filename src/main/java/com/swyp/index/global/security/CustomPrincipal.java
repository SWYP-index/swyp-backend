package com.swyp.index.global.security;

import java.security.Principal;

public record CustomPrincipal(Long id) implements Principal {

	@Override
	public String getName() {
		return String.valueOf(id);
	}

	public Long getId() {
		return id;
	}
}