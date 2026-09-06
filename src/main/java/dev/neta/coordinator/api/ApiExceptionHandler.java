package dev.neta.coordinator.api;

import dev.neta.coordinator.protocol.ProtocolException;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(ProtocolException.class)
    ResponseEntity<Map<String,Object>> protocol(ProtocolException e) {
        return ResponseEntity.status(e.status()).body(error(e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<Map<String,Object>> malformed(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest().body(error("malformed protocol message"));
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String,Object>> status(ResponseStatusException e) {
        String message = e.getReason() == null || e.getReason().isBlank() ? "request failed" : e.getReason();
        return ResponseEntity.status(e.getStatusCode()).body(error(message));
    }

    private static Map<String,Object> error(String message) {
        return Map.of("error", message, "timestamp", Instant.now().toString());
    }
}
