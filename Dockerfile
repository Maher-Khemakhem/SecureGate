# ---- Build stage -------------------------------------------------------------
FROM maven:3.9.9-eclipse-temurin-17 AS build
WORKDIR /build

# Cache dependencies separately from sources
COPY pom.xml .
RUN mvn -q -B dependency:go-offline

COPY src ./src
# docker build --build-arg SKIP_TESTS=true . to skip the test suite
ARG SKIP_TESTS=false
RUN mvn -q -B package -DskipTests=${SKIP_TESTS}

# ---- Runtime stage -----------------------------------------------------------
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

RUN addgroup -S securegate && adduser -S securegate -G securegate \
    && mkdir -p /app/logs && chown -R securegate:securegate /app

COPY --from=build --chown=securegate:securegate /build/target/securegate-exec.jar /app/securegate.jar

USER securegate
EXPOSE 8080
VOLUME ["/app/logs"]

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/securegate.jar"]
