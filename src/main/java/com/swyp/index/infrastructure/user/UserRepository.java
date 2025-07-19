package com.swyp.index.infrastructure.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.swyp.index.domain.user.Provider;
import com.swyp.index.domain.user.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findById(Long id);

	Optional<User> findByEmailAndProvider(String email, Provider provider);

	boolean existsByEmail(String email);

	boolean existsByNickname(String nickname);
}