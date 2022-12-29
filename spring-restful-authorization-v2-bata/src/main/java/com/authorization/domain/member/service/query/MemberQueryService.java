package com.authorization.domain.member.service.query;

import com.authorization.common.config.authentication.model.transfer.UserDetailsImpl;
import com.authorization.common.config.oauth2.model.response.OAuth2Token;
import com.authorization.common.config.oauth2.model.response.userInfo.OAuth2UserInfo;
import com.authorization.domain.config.model.entity.Config;
import com.authorization.domain.config.service.ConfigService;
import com.authorization.domain.member.enums.MemberType;
import com.authorization.domain.member.model.entity.Member;
import com.authorization.domain.member.repository.MemberRepository;
import com.authorization.domain.member.service.MemberService;
import com.authorization.domain.memberSocial.enums.Provider;
import com.authorization.domain.memberSocial.model.entity.MemberSocial;
import com.authorization.domain.memberSocial.repository.MemberSocialRepository;
import com.authorization.domain.role.model.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Slf4j
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberQueryService {

    private final MemberService memberService;
    private final ConfigService configService;
    private final MemberRepository memberRepository;
    private final MemberSocialRepository memberSocialRepository;

    public Member selectMemberById(String username) {
        return memberRepository.findByIdAndUseYn(username, true);
    }

    public UserDetails loginOAuth2User(Provider provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {

        MemberSocial memberSocial = memberSocialRepository.selectMemberSocialByProviderAndProviderId(provider, userInfo.getId());
        Member member = null;

        //가입된 계정이 존재할때
        if (memberSocial != null) {
            member = memberSocial.getMember();
            //토큰 업데이트
            memberSocial.updateToken(oAuth2Token.getAccessToken(), oAuth2Token.getRefreshToken(), oAuth2Token.getExpiredAt());

            memberService.saveMemberSocial(memberSocial);
        }
        //가입된 계정이 존재하지 않을때
        else {
            //소셜 계정 정보 생성
            MemberSocial newMemberSocial = MemberSocial.builder()
                    .provider(provider)
                    .providerId(userInfo.getId())
                    .accessToken(oAuth2Token.getAccessToken())
                    .refreshToken(oAuth2Token.getRefreshToken())
                    .expiredAt(oAuth2Token.getExpiredAt()).build();

            //oAuth2AccountRepository.save(newAccount);

            String id = provider.getProvider() + "_" + userInfo.getId();

            Config config = configService.selectConfig();
            Role clientRole = config.getClientRole();

            //이메일 정보가 있을때
            if (userInfo.getEmail() != null) {

                // 같은 이메일을 사용하는 계정이 존재하는지 확인 후 있다면 소셜 계정과 연결시키고 없다면 새로 생성한다
                member = memberRepository.findByEmail(userInfo.getEmail())
                        .orElse(Member.builder()
                                .email(userInfo.getEmail())
                                .name(id)
                                .id(id)
                                .todayLogin(LocalDateTime.now())
                                .memberType(MemberType.OAUTH)
                                .role(clientRole)
                                .build());
            }
            //이메일 정보가 없을때
            else {
                member = Member.builder()
                        .email(userInfo.getEmail())
                        .name(id)
                        .id(id)
                        .todayLogin(LocalDateTime.now())
                        .memberType(MemberType.OAUTH)
                        .role(clientRole)
                        .build();
            }

            member.setMemberSocial(newMemberSocial);
            memberService.saveMember(member);
/*            //새로 생성된 유저이면 db에 저장
            if (member.getId() == null)
                userRepository.save(member);

            //연관관계 설정
            member.linkSocial(newAccount);*/
        }

        return UserDetailsImpl.builder()
                .id(member.getMemberNo())
                .username(member.getId())
                .name(member.getName())
                .email(member.getEmail())
                .memberType(member.getMemberType())
                .authorities(member.getAuthorities()).build();
    }

    public void linkOAuth2Account(String username, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo oAuth2UserInfo) {

    }
}
