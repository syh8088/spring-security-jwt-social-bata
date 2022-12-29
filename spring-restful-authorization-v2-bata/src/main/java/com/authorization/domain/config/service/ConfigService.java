package com.authorization.domain.config.service;

import com.authorization.domain.config.model.entity.Config;
import com.authorization.domain.config.repository.ConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ConfigService {

    private final ConfigRepository configRepository;

    public Config selectConfig() {
        return configRepository.selectConfig();
    }
}
