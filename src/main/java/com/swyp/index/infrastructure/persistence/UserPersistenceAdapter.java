package com.swyp.index.infrastructure.persistence;

import com.swyp.index.application.port.out.UserPort;
import com.swyp.index.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;
/**
 * UserPort 인터페이스를 실제 JPA 기술로 구현하는 어댑터 클래스입니다.
 * 애플리케이션 서비스는 이 어댑터를 통해 DB에 접근하게 됩니다.
 */
@Repository
@RequiredArgsConstructor
public class UserPersistenceAdapter implements UserPort {

    private final UserJpaRepository userJpaRepository;

    @Override
    public Optional<User> findByEmail(String email) {
        return Optional.empty();
    }

    @Override
    public boolean existsByEmail(String email) {
        return false;
    }

    @Override
    public boolean existsByNickname(String nickname) {
        return false;
    }

    @Override
    public User save(User user) {
        return null;
    }
}
