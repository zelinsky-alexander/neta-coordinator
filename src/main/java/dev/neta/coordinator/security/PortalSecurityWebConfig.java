package dev.neta.coordinator.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class PortalSecurityWebConfig implements WebMvcConfigurer {
    private final PortalReadAuthorizationInterceptor readInterceptor;
    private final PortalMutationAuthorizationInterceptor mutationInterceptor;

    public PortalSecurityWebConfig(PortalReadAuthorizationInterceptor readInterceptor,
                                   PortalMutationAuthorizationInterceptor mutationInterceptor) {
        this.readInterceptor = readInterceptor;
        this.mutationInterceptor = mutationInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(readInterceptor);
        registry.addInterceptor(mutationInterceptor);
    }
}
