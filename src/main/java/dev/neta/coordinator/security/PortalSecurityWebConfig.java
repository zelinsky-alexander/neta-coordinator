package dev.neta.coordinator.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class PortalSecurityWebConfig implements WebMvcConfigurer {
    private final PortalReadAuthorizationInterceptor interceptor;

    public PortalSecurityWebConfig(PortalReadAuthorizationInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(interceptor);
    }
}
