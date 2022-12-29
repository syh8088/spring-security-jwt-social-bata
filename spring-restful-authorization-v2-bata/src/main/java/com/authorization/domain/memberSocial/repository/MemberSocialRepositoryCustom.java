package com.authorization.domain.memberSocial.repository;

import com.authorization.domain.memberSocial.model.entity.MemberSocial;
import com.authorization.domain.memberSocial.enums.Provider;

public interface MemberSocialRepositoryCustom {
    MemberSocial selectMemberSocialByProviderAndProviderId(Provider provider, String providerId);
}
