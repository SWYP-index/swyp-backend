# 1단계: 빌드된 JAR 파일만 사용하는 경량 이미지
FROM openjdk:21-jdk-slim

# 작업 디렉토리 설정
WORKDIR /app

# 빌드된 JAR 파일을 이미지에 복사
COPY build/libs/*.jar app.jar

# 포트 노출 (옵션)
EXPOSE 8080

# 컨테이너 실행 시 실행할 명령어
CMD ["java", "-jar", "app.jar"]
