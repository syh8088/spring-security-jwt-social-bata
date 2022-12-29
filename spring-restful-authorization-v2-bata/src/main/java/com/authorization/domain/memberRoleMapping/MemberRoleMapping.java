package com.authorization.domain.memberRoleMapping;

import com.authorization.common.entity.Common;
import com.authorization.domain.member.model.entity.Member;
import com.authorization.domain.role.model.entity.Role;
import lombok.*;

import javax.persistence.*;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class MemberRoleMapping extends Common {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberRoleMappingNo;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_no")
    private Member member;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_no")
    private Role role;

    @Builder
    public MemberRoleMapping(Long memberRoleMappingNo, Member member, Role role) {
        this.memberRoleMappingNo = memberRoleMappingNo;
        this.member = member;
        this.role = role;
    }
}
