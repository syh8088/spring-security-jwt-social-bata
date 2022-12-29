package com.authorization.common.config.error.validator;

import com.authorization.common.config.authentication.model.request.AuthorizationRequest;
import com.authorization.common.config.error.errorCode.MemberErrorCode;
import com.authorization.common.config.error.exception.CommonException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

@Component
public class MemberValidator {

    public void authenticateUsernamePassword(AuthorizationRequest authorizationRequest) {

        if (StringUtils.isBlank(authorizationRequest.getUsername()) || StringUtils.isBlank(authorizationRequest.getPassword())) {
            throw new CommonException(MemberErrorCode.NOT_EXIST_USERNAME_OR_PASSWORD);
        }
    }
}
