package com.swyp.index.infrastructure.User;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.swyp.index.domain.User.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByEmail(String email);
	boolean existsByEmail(String email);
	boolean existsByNickname(String nickname);
}