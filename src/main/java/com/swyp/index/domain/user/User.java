package com.swyp.index.domain.user;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EntityListeners(AuditingEntityListener.class)
@Table(uniqueConstraints = {@UniqueConstraint(columnNames = {"email", "provider"})})
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String email;

	private String nickname;

	private String password;

	@Enumerated(value = EnumType.STRING)
	private Provider provider;

	private String providerId;

	@CreatedDate
	@Column(updatable = false)
	private LocalDateTime createdAt;

	@LastModifiedDate
	private LocalDateTime updatedAt;

	public static User fromSocial(String provider, OAuth2UserInfo userInfo) {
		User user = new User();

		user.email = userInfo.getEmail();
		user.nickname = userInfo.getName();
		user.provider = Provider.valueOf(provider.toUpperCase());
		user.providerId = userInfo.getProviderId();

		return user;
	}

	public static User ofLocal(String email, String nickname, String password, String provider) {
		User user = new User();

		user.email = email;
		user.nickname = nickname;
		user.password = password;
		user.provider = Provider.valueOf(provider.toUpperCase());

		return user;
	}

	public void update(String nickname, String provider, String providerId) {
		this.nickname = nickname;
		this.provider = Provider.valueOf(provider.toUpperCase());
		this.providerId = providerId;
	}
}