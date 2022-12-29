package com.authorization.domain.member.enums;

import lombok.Getter;

import java.util.Arrays;

@Getter
public enum MemberType {

    DEFAULT("DEFAULT"),
    OAUTH("OAUTH");

    private final String memberType;

    MemberType(String memberType) {
        this.memberType = memberType;
    }

    public String getMemberType() {
        return this.memberType;
    }

    public static MemberType getByMemberType(String memberType) {
        return Arrays.stream(MemberType.values())
                .filter(data -> data.getMemberType().equals(memberType))
                .findFirst()
                .orElse(MemberType.DEFAULT);
    }
}
