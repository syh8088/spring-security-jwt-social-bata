package com.authorization.domain.member.service;

import com.authorization.domain.member.model.entity.Member;
import com.authorization.domain.member.repository.MemberRepository;
import com.authorization.domain.memberSocial.model.entity.MemberSocial;
import com.authorization.domain.memberSocial.repository.MemberSocialRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final MemberSocialRepository memberSocialRepository;

    public void saveMember(Member member) {

        memberRepository.save(member);
    }

    public void saveMemberSocial(MemberSocial memberSocial) {

        memberSocialRepository.save(memberSocial);
    }
}
