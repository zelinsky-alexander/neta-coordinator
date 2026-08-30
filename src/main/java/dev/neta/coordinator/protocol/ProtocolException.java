package dev.neta.coordinator.protocol;

import org.springframework.http.HttpStatus;

public final class ProtocolException extends RuntimeException {
    private final HttpStatus status;
    public ProtocolException(HttpStatus status, String message) { super(message); this.status = status; }
    public HttpStatus status() { return status; }
    public static ProtocolException badRequest(String message) { return new ProtocolException(HttpStatus.BAD_REQUEST, message); }
    public static ProtocolException unauthorized(String message) { return new ProtocolException(HttpStatus.UNAUTHORIZED, message); }
    public static ProtocolException conflict(String message) { return new ProtocolException(HttpStatus.CONFLICT, message); }
}
