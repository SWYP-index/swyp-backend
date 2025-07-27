package com.swyp.index.global.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(CustomException.class)
	public ResponseEntity<ErrorResponse> handleCustomException(CustomException ex) {
		ErrorResponse response = new ErrorResponse(ex.getErrorCode());

		log.warn("CustomException Occurred: status={}, code={}, message={}",
			response.getStatus(), ex.getErrorCode().name(), response.getMessage());

		return ResponseEntity
				.status(response.getStatus())
				.body(response);
	}

	/**
	 * @Valid 어노테이션 유효성 검사 실패 시 발생하는 예외를 처리하는 핸들러
	 */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
		String errorMessage = ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();

		// 에러 메시지를 담은 커스텀 BAD_REQUEST 코드가 없다면 INVALID_INPUT_VALUE를 쓰는게 일반적입니다.
		ErrorResponse response = new ErrorResponse(ErrorCode.INVALID_INPUT_VALUE);

		log.warn("MethodArgumentNotValidException Occurred: {}", errorMessage);

		return ResponseEntity
			.status(HttpStatus.BAD_REQUEST)
			.body(response);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> handleException(Exception ex) {
		log.error("Unhandled Exception Occurred: {}", ex.getMessage(), ex);

		ErrorResponse response = new ErrorResponse(ErrorCode.INTERNAL_SERVER_ERROR);

		return ResponseEntity
			.status(HttpStatus.INTERNAL_SERVER_ERROR)
			.body(response);
	}
}
