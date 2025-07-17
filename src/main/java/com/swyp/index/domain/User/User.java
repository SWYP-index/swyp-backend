package com.swyp.index.domain.User;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
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
@EntityListeners(AuditingEntityListener.class)
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// @Column(nullable = false, unique = true)
	private String email;

	// @Column(nullable = false, length = 50)
	private String nickname;

	private String password;

	@Enumerated(value = EnumType.STRING)
	// @Column(nullable = false)
	private ProviderType provider;

	// @Column(unique = true)
	private String providerId;

	// private Role role;

	// @CreatedDate
	// @Column(name = "created_at", updatable = true, nullable = true)
	// private LocalDateTime createdAt;
	//
	// @LastModifiedDate
	// @Column(name = "updated_at", nullable = true)
	// private LocalDateTime updatedAt;

	public static User of(String email, String name, String provider, String providerId) {
		User user = new User();

		user.email = email;
		user.nickname = name;
		user.provider = ProviderType.valueOf(provider.toUpperCase());
		user.providerId = providerId;

		return user;
	}

	public static User ofLocal(String email, String name, String password, String provider) {
		User user = new User();

		user.email = email;
		user.nickname = name;
		user.password = password;
		user.provider = ProviderType.valueOf(provider.toUpperCase());

		return user;
	}


	public void update(String nickname, String provider, String providerId) {
		this.nickname = nickname;
		this.provider = ProviderType.valueOf(provider.toUpperCase());
		this.providerId = providerId;
	}
}