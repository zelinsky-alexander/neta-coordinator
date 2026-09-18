package dev.neta.coordinator;

import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class FlywayMigrationVersionTest {
    private static final Path MIGRATION_DIRECTORY =
            Path.of("src", "main", "resources", "db", "migration");
    private static final Pattern VERSIONED_MIGRATION =
            Pattern.compile("^V([^_]+(?:_[^_]+)*)__.+\\.sql$");

    @Test
    void versionedMigrationsHaveUniqueVersions() throws IOException {
        Map<String, Path> migrationsByVersion = new HashMap<>();

        try (Stream<Path> migrations = Files.list(MIGRATION_DIRECTORY)) {
            migrations.filter(Files::isRegularFile)
                    .sorted()
                    .forEach(path -> recordVersion(migrationsByVersion, path));
        }
    }

    private static void recordVersion(Map<String, Path> migrationsByVersion, Path path) {
        Matcher matcher = VERSIONED_MIGRATION.matcher(path.getFileName().toString());
        if (!matcher.matches()) {
            return;
        }

        String version = matcher.group(1).replace('_', '.');
        Path previous = migrationsByVersion.putIfAbsent(version, path);
        assertNull(previous,
                () -> "duplicate Flyway migration version " + version
                        + ": " + previous.getFileName() + " and " + path.getFileName());
    }
}
