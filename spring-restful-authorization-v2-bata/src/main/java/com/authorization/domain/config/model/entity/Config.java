package com.authorization.domain.config.model.entity;

import com.authorization.common.entity.CommonExclusionOfUseYn;
import com.authorization.domain.role.model.entity.Role;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Config extends CommonExclusionOfUseYn {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long configNo;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_role_no")
    private Role clientRole;
}
