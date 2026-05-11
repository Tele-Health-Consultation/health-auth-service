package com.health.management.exceptions;

import com.health.management.constants.ErrorBuilder;
import com.health.management.dto.ErrorDto;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ErrorDto globalException(Exception exception, WebRequest request) {
        return ErrorBuilder.buildError(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ErrorDto userNotFoundException(UserNotFoundException exception, WebRequest request) {
        return ErrorBuilder.buildError(HttpStatus.NOT_FOUND, exception.getMessage(), request);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ErrorDto badCredentialsException(BadCredentialsException exception, WebRequest request) {
        return ErrorBuilder.buildError(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    @ExceptionHandler(JwtException.class)
    public ErrorDto jwtException(JwtException exception, WebRequest request) {
        return ErrorBuilder.buildError(HttpStatus.UNAUTHORIZED, exception.getMessage(), request);
    }
}
