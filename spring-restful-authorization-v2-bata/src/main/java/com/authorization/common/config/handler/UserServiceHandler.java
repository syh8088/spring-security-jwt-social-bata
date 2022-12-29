package com.authorization.common.config.handler;

import com.authorization.common.config.authentication.model.transfer.UserDetailsImpl;
import com.authorization.common.config.error.errorCode.MemberErrorCode;
import com.authorization.common.config.error.exception.UserIdNotFoundException;
import com.authorization.domain.member.model.entity.Member;
import com.authorization.domain.member.service.query.MemberQueryService;
import com.authorization.domain.role.model.entity.Role;
import com.authorization.domain.role.service.query.RoleQueryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceHandler implements UserDetailsService {

    private final MemberQueryService memberQueryService;
    private final RoleQueryService roleQueryService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member member = memberQueryService.selectMemberById(username);

        if (member == null) {
            throw new UserIdNotFoundException(MemberErrorCode.NOT_FOUND_USERNAME);
        }

        List<Role> roles = roleQueryService.selectAllRolesByMember(member);

        List<SimpleGrantedAuthority> grants = roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());

        UserDetailsImpl userDetails = UserDetailsImpl.builder()
                .id(member.getMemberNo())
                .username(member.getId())
                .name(member.getName())
                .email(member.getEmail())
                .password(member.getPassword())
                .memberType(member.getMemberType())
                .authorities(grants)
                .build();

        return userDetails;
    }
}
