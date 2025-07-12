package com.swyp.index.repository;

import com.swyp.index.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    //이메일로 사용자를 찾는 메서드
    Optional<User> findByEmail(String email);
    //이메일로 사용자의 존재 여부를 확인하는 메서드
    boolean existsByEmail(String email);
    //닉네임 중복 확인을 위한 메서드
    boolean existsByNickname(String nickname);
}
