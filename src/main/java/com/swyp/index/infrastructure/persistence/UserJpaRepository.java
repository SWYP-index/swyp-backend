package com.swyp.index.infrastructure.persistence;

import com.swyp.index.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
/**
 * Spring Data JPA를 사용하여 데이터베이스와 통신하는 실제 리포지토리 인터페이스입니다.
 */
public interface UserJpaRepository extends JpaRepository<User, Long> {

    // Spring Data JPA가 메서드 이름을 보고 자동으로 쿼리를 생성합니다.
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    boolean existsByNickname(String nickname);
}