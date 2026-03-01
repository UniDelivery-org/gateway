package org.unidelivery.gateway.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class ErrorResponse {
    private String message;
    private String errorCode;
    private HttpStatus status;
    private LocalDateTime timestamp;
    private List<String> details;
}
