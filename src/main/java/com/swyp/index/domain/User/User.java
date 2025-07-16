package com.swyp.index.domain.User;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String email;

	private String nickname;

	private String password;

	@Enumerated(value = EnumType.STRING)
	private ProviderType provider;

	private String providerId;

	public static User of(String email, String name, String provider, String providerId) {
		User user = new User();

		user.email = email;
		user.nickname = name;
		user.provider = ProviderType.valueOf(provider.toUpperCase());
		user.providerId = providerId;

		return user;
	}

	public void update(String nickname, String provider, String providerId) {
		this.nickname = nickname;
		this.provider = ProviderType.valueOf(provider.toUpperCase());
		this.providerId = providerId;
	}
}