package com.authorization.domain.resources.repository;

import com.authorization.domain.resources.model.entity.Resource;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResourceRepository extends JpaRepository<Resource, Long> {
}
