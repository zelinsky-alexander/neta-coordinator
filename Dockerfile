FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B -DskipTests package

FROM eclipse-temurin:21-jre-jammy
RUN useradd --system --uid 10001 --create-home neta
WORKDIR /app
COPY --from=build /workspace/target/neta-coordinator-*.jar /app/neta-coordinator.jar
USER 10001
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/neta-coordinator.jar"]
