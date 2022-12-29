package com.authorization.domain.role.repository;

import com.authorization.domain.member.model.entity.Member;
import com.authorization.domain.role.model.entity.Role;

import java.util.List;

public interface RoleRepositoryCustom {

    List<Role> selectAllRolesByMember(Member member);
}
