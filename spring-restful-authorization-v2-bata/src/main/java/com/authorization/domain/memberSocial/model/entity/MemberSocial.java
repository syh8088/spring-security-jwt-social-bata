package com.authorization.domain.memberSocial.model.entity;

import com.authorization.common.entity.CommonExclusionOfUseYn;
import com.authorization.domain.member.model.entity.Member;
import com.authorization.domain.memberSocial.enums.Provider;
import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MemberSocial extends CommonExclusionOfUseYn {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberSocialNo;

    @Enumerated(value = EnumType.STRING)
    private Provider provider;

    private String providerId;

    private String accessToken;

    private String refreshToken;

    private LocalDateTime expiredAt;

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "memberSocial")
    private Member member;

    @Builder
    public MemberSocial(Provider provider, String providerId, String accessToken, String refreshToken, LocalDateTime expiredAt) {
        this.provider = provider;
        this.providerId = providerId;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiredAt = expiredAt;
    }

    public void updateToken(String accessToken, String refreshToken, LocalDateTime expiredAt) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiredAt = expiredAt;
    }
}
