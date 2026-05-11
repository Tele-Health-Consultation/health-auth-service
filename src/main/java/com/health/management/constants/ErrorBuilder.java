package com.health.management.constants;

import com.health.management.dto.ErrorDto;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.WebRequest;
import java.time.Instant;

public class ErrorBuilder {

    public static ErrorDto buildError(HttpStatus status, String message, WebRequest request) {
        return ErrorDto.builder()
                .message(message)
                .status(status)
                .time(Instant.now())
                .uriPath(request == null ? "" : request.getDescription(false))
                .build();
    }

    public static ErrorDto buildError(HttpStatus status, String message) {
        return buildError(status, message, null);
    }
}
