package com.authorization.domain.role.model.entity;

import com.authorization.common.entity.Common;
import com.authorization.domain.memberRoleMapping.MemberRoleMapping;
import lombok.*;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "role")
public class Role extends Common {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long roleNo;

    @Column(nullable = false)
    private String name;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "role")
    private List<MemberRoleMapping> memberRoleMappings = new ArrayList<>();
}
