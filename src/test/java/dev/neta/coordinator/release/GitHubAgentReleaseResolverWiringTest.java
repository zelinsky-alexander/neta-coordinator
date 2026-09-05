package dev.neta.coordinator.release;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.neta.coordinator.config.AgentReleaseProperties;
import java.lang.reflect.Constructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class GitHubAgentReleaseResolverWiringTest {

    @Test
    void productionConstructorIsExplicitlyAutowiredWhenTestConstructorAlsoExists() throws Exception {
        Constructor<GitHubAgentReleaseResolver> constructor = GitHubAgentReleaseResolver.class.getConstructor(
                ObjectMapper.class, AgentReleaseProperties.class, JdbcTemplate.class);

        assertNotNull(constructor.getAnnotation(Autowired.class),
                "Spring must use the production constructor instead of attempting default construction");
    }
}
