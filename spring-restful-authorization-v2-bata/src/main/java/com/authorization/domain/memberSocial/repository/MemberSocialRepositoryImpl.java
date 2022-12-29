package com.authorization.domain.memberSocial.repository;

import com.authorization.domain.member.model.entity.QMember;
import com.authorization.domain.memberSocial.model.entity.MemberSocial;
import com.authorization.domain.memberSocial.enums.Provider;
import com.authorization.domain.memberSocial.model.entity.QMemberSocial;
import com.querydsl.core.BooleanBuilder;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

public class MemberSocialRepositoryImpl extends QuerydslRepositorySupport implements MemberSocialRepositoryCustom {

    /**
     * Creates a new {@link QuerydslRepositorySupport} instance for the given domain type.
     *
     * @param domainClass must not be {@literal null}.
     */
    public MemberSocialRepositoryImpl() {
        super(MemberSocial.class);
    }

    QMember qMember = QMember.member;
    QMemberSocial qMemberSocial = QMemberSocial.memberSocial;

    @Override
    public MemberSocial selectMemberSocialByProviderAndProviderId(Provider provider, String providerId) {

        BooleanBuilder booleanBuilder = new BooleanBuilder();
        booleanBuilder.and(qMemberSocial.provider.eq(provider));
        booleanBuilder.and(qMemberSocial.providerId.eq(providerId));

        return from(qMemberSocial)
                .leftJoin(qMemberSocial.member, qMember).fetchJoin()
                .where(booleanBuilder)
                .fetchOne();
    }
}
