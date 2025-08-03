package com.swyp.index.global.exception;

import jakarta.servlet.http.HttpServletRequest;
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
	public ResponseEntity<ErrorResponse> handleCustomException(CustomException ex, HttpServletRequest request) {
		ErrorResponse response = new ErrorResponse(ex.getErrorCode());

		log.error("CustomException Occurred: uri={} method={} status={}, code={}, message={}",
			request.getRequestURI(),request.getMethod(),response.getStatus(), ex.getErrorCode().name(), response.getMessage(),ex);

		return ResponseEntity
				.status(response.getStatus())
				.body(response);
	}

	/**
	 * @Valid 어노테이션 유효성 검사 실패 시 발생하는 예외를 처리하는 핸들러
	 */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(
			MethodArgumentNotValidException ex,
			HttpServletRequest req
	) {
		String errorMessage = ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();
		ErrorResponse response = new ErrorResponse(ErrorCode.INVALID_INPUT_VALUE);

		log.error("[ValidationException] uri={} method={} message={}",
				req.getRequestURI(),
				req.getMethod(),
				errorMessage,
				ex
		);

		return ResponseEntity
				.status(HttpStatus.BAD_REQUEST)
				.body(response);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> handleException(
			Exception ex,
			HttpServletRequest req
	) {
		log.error("[UnhandledException] uri={} method={} message={}",
				req.getRequestURI(),
				req.getMethod(),
				ex.getMessage(),
				ex
		);

		ErrorResponse response = new ErrorResponse(ErrorCode.INTERNAL_SERVER_ERROR);

		return ResponseEntity
				.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(response);
	}
}