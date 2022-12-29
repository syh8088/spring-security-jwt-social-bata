package com.authorization.domain.config.controller;

import com.authorization.domain.config.service.ConfigService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("configs")
public class ConfigController {

    private final ConfigService configService;

}
