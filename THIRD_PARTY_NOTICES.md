# Third-party notices

NETA Coordinator is Apache-2.0 licensed. Its Maven dependency graph includes third-party software under compatible licenses.

Direct dependencies introduced by this project:

- Spring Boot and Spring Framework — Apache License 2.0 — web/service framework, JDBC integration, validation, health/metrics. Actively maintained by Broadcom/Spring.
- PostgreSQL JDBC Driver — BSD 2-Clause — PostgreSQL connectivity. Actively maintained by the pgJDBC project.
- Flyway Community/core components used here — Apache License 2.0 — database schema migrations. Actively maintained by Redgate. Commercial Flyway features are not required by this project.
- JUnit and test libraries brought by `spring-boot-starter-test` — permissive/open-source licenses managed by Spring Boot dependency management — unit testing only.

This notice is informational and does not replace the license texts distributed by dependencies. Before publishing binary distributions, review the resolved dependency tree and bundled license notices as part of the release process.
