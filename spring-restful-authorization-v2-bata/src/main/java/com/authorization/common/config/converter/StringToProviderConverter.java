package com.authorization.common.config.converter;

import com.authorization.domain.memberSocial.enums.Provider;
import org.springframework.core.convert.converter.Converter;

public class StringToProviderConverter implements Converter<String, Provider> {

    @Override
    public Provider convert(String source) {

        return Provider.getByProvider(source);
    }
}
