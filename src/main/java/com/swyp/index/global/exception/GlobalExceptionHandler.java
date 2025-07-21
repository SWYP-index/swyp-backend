package com.swyp.index.global.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(CustomException.class)
	public ResponseEntity<ErrorResponse> handleCustomException(CustomException ex) {
		log.info("Custom exception occurred: {}", ex.getMessage(), ex);

		ErrorCode code = ex.getErrorCode();

		ErrorResponse response = new ErrorResponse(code.getStatusCode(), code.getMessage());

		return ResponseEntity.status(code.getStatusCode()).body(response);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<String> handleException(Exception ex) {
		log.info("Unhandled exception occurred: {}", ex.getMessage(), ex);

		return ResponseEntity
			.status(HttpStatus.INTERNAL_SERVER_ERROR)
			.body("서버 오류가 발생했습니다.");
	}
}
