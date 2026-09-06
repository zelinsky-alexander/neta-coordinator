package dev.neta.coordinator.security;

import dev.neta.coordinator.api.PortalReadApiController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class PortalReadAuthorizationInterceptor implements HandlerInterceptor {
    private final PortalAuthorization authorization;

    public PortalReadAuthorizationInterceptor(PortalAuthorization authorization) {
        this.authorization = authorization;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method) || method.getBeanType() != PortalReadApiController.class) return true;
        authorization.requireRead(
                request.getHeader("X-NETA-Portal-Service-Token"),
                request.getHeader("X-NETA-Actor"),
                request.getHeader("X-NETA-Actor-Role"),
                request.getHeader("X-NETA-Portal-Service"),
                request.getHeader("X-Request-ID"));
        return true;
    }
}
