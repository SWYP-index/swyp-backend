# 1단계: 빌드 스테이지
FROM gradle:8.7.0-jdk21-jammy AS builder

WORKDIR /app

COPY --chown=gradle:gradle . /app

RUN gradle clean build --no-daemon

# 2단계: 실행 스테이지
FROM openjdk:21-jdk-slim

WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]