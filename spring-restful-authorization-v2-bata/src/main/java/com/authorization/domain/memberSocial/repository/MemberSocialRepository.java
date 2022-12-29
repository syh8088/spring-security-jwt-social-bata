package com.authorization.domain.memberSocial.repository;

import com.authorization.domain.memberSocial.model.entity.MemberSocial;
import com.authorization.domain.memberSocial.enums.Provider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberSocialRepository extends JpaRepository<MemberSocial, Long>, MemberSocialRepositoryCustom {


    Optional<MemberSocial> findByProviderAndProviderId(Provider provider, String id);

}
