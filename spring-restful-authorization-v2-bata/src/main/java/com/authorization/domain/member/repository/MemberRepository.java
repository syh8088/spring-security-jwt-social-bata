package com.authorization.domain.member.repository;

import com.authorization.domain.member.model.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Member findByIdAndUseYn(String id, boolean useYn);
    Optional<Member> findByEmail(String email);
}
