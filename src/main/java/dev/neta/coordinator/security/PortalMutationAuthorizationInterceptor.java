package dev.neta.coordinator.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.api.AgentAdminController;
import dev.neta.coordinator.api.AgentUpgradeController;
import dev.neta.coordinator.api.CertificateOperatorController;
import dev.neta.coordinator.api.FindingBulkController;
import dev.neta.coordinator.api.FindingDispositionController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class PortalMutationAuthorizationInterceptor implements HandlerInterceptor {
    private static final String ACTOR_ATTRIBUTE = "neta.portal.actor";
    private static final String OPERATION_ATTRIBUTE = "neta.portal.operation";

    private final PortalAuthorization authorization;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public PortalMutationAuthorizationInterceptor(PortalAuthorization authorization, JdbcTemplate jdbc, ObjectMapper mapper) {
        this.authorization = authorization;
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method)) return true;
        Required required = required(method);
        if (required == null) return true;

        String portalToken = request.getHeader("X-NETA-Portal-Service-Token");
        if (portalToken == null || portalToken.isBlank()) return true; // trusted legacy CLI/admin-token path

        PortalAuthorization.Actor actor = authorization.require(
                portalToken,
                request.getHeader("X-NETA-Actor"),
                request.getHeader("X-NETA-Actor-Role"),
                request.getHeader("X-NETA-Portal-Service"),
                request.getHeader("X-Request-ID"),
                request.getHeader("Idempotency-Key"),
                required.role());
        request.setAttribute(ACTOR_ATTRIBUTE, actor);
        request.setAttribute(OPERATION_ATTRIBUTE, required.operation());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        Object actorValue = request.getAttribute(ACTOR_ATTRIBUTE);
        Object operationValue = request.getAttribute(OPERATION_ATTRIBUTE);
        if (!(actorValue instanceof PortalAuthorization.Actor actor) || operationValue == null) return;
        try {
            Map<String,Object> details = new LinkedHashMap<>();
            details.put("actor_user", actor.user());
            details.put("actor_role", actor.role().name());
            details.put("via_service", actor.service());
            details.put("operation", operationValue.toString());
            details.put("request_id", actor.requestId());
            details.put("idempotency_key", actor.idempotencyKey());
            details.put("http_status", response.getStatus());
            details.put("result", ex == null && response.getStatus() < 400 ? "SUCCESS" : "FAILED");
            details.put("path", request.getRequestURI());
            String agent = request.getParameter("agent");
            if (agent != null && !agent.isBlank()) details.put("requested_agent", agent);
            String finding = request.getParameter("id");
            if (finding != null && !finding.isBlank()) details.put("requested_finding", finding);
            jdbc.update("INSERT INTO audit_events(event_type,agent_id,details) VALUES ('PORTAL_OPERATOR_ACTION',NULL,CAST(? AS jsonb))",
                    mapper.writeValueAsString(details));
        } catch (Exception ignored) {
            // Domain operations must not be rolled back merely because supplemental portal audit enrichment failed.
            // Existing domain audit remains authoritative; failed enrichment is observable through application logging in future hardening.
        }
    }

    private static Required required(HandlerMethod method) {
        Class<?> bean = method.getBeanType();
        String name = method.getMethod().getName();
        if (bean == AgentUpgradeController.class && name.equals("requestUpgrade"))
            return new Required(PortalAuthorization.Role.OPERATOR, "AGENT_UPGRADE_REQUEST");
        if (bean == AgentAdminController.class && name.equals("revoke"))
            return new Required(PortalAuthorization.Role.ADMIN, "AGENT_REVOKE");
        if (bean == AgentAdminController.class && name.equals("reactivate"))
            return new Required(PortalAuthorization.Role.ADMIN, "AGENT_REACTIVATE");
        if (bean == CertificateOperatorController.class && name.equals("rotate"))
            return new Required(PortalAuthorization.Role.ADMIN, "CERTIFICATE_ROTATE");
        if (bean == FindingDispositionController.class && name.equals("suppress"))
            return new Required(PortalAuthorization.Role.OPERATOR, "FINDING_SUPPRESS");
        if (bean == FindingDispositionController.class && name.equals("falsePositive"))
            return new Required(PortalAuthorization.Role.OPERATOR, "FINDING_FALSE_POSITIVE");
        if (bean == FindingBulkController.class && name.equals("resolve"))
            return new Required(PortalAuthorization.Role.OPERATOR, "FINDINGS_BULK_RESOLVE");
        if (bean == FindingBulkController.class && name.equals("purge"))
            return new Required(PortalAuthorization.Role.ADMIN, "FINDINGS_BULK_PURGE");
        return null;
    }

    private record Required(PortalAuthorization.Role role, String operation) {}
}
