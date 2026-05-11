package com.health.management.constants;

import com.health.management.dto.ResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.WebRequest;
import java.time.Instant;

public class ResponseBuilder {

    public static <T> ResponseDto<T> buildResponse(T response, HttpStatus status, WebRequest request){
        return ResponseDto.<T>builder()
                .status(status)
                .responseTime(Instant.now())
                .response(response)
                .uriPath(request == null ? "" : request.getDescription(false))
                .build();
    }

    public static <T> ResponseDto<T> buildResponse(T response, HttpStatus status){
        return buildResponse(response, status, null);
    }
}
