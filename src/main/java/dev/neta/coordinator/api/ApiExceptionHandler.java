package dev.neta.coordinator.api;

import dev.neta.coordinator.protocol.ProtocolException;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(ProtocolException.class)
    ResponseEntity<Map<String,Object>> protocol(ProtocolException e) {
        return ResponseEntity.status(e.status()).body(Map.of("error", e.getMessage(), "timestamp", Instant.now().toString()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<Map<String,Object>> malformed(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "malformed protocol message", "timestamp", Instant.now().toString()));
    }
}
