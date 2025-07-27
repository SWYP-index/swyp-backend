package com.swyp.index.infrastructure.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.swyp.index.domain.user.Provider;
import com.swyp.index.domain.user.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByEmailAndProvider(String email, Provider provider);

	boolean existsByEmailAndProvider(String email, Provider provider);

	boolean existsByNickname(String nickname);
}