package com.authorization.common.config.error.exception;

import com.authorization.common.config.error.model.CommonErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
public class GlobalExceptionController {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = CommonException.class)
    @ResponseBody
    public CommonErrorResponse handleCommonException(CommonException e) {

        return CommonErrorResponse.builder()
                .errorCode(e.getErrorCode())
                .message(e.getMessage())
                .status(HttpStatus.BAD_REQUEST.value())
                .build();
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(value = AuthenticationFailedException.class)
    @ResponseBody
    public CommonErrorResponse handleAuthenticationFailedException(AuthenticationFailedException e) {

        return CommonErrorResponse.builder()
                .errorCode(e.getErrorCode())
                .message(e.getMessage())
                .status(HttpStatus.FORBIDDEN.value())
                .build();
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(value = UserIdNotFoundException.class)
    @ResponseBody
    public CommonErrorResponse handleUsernameNotFoundException(UserIdNotFoundException e) {

        return CommonErrorResponse.builder()
                .errorCode(e.getErrorCode())
                .message(e.getMessage())
                .status(HttpStatus.NOT_FOUND.value())
                .build();
    }

    @ExceptionHandler(value = Exception.class)
    public String handleException() {
        return "error";
    }

}
