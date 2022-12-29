package com.authorization.domain.resources.model.entity;

import com.authorization.common.entity.Common;
import lombok.*;

import javax.persistence.*;

@Entity
@Getter
@Setter
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "resources")
public class Resource extends Common {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long resourceNo;

    private String resourceName;

    private Long orderNum;

    private String resourceType;
}
