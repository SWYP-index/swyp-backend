package com.swyp.index.global.exception;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class ErrorResponse {

	private int status;
	private String code;
	private String message;
	private String timestamp;

	public ErrorResponse(ErrorCode errorCode) {
		this.status = errorCode.getStatusCode();
		this.code = errorCode.name();
		this.message = errorCode.getMessage();
		this.timestamp = java.time.OffsetDateTime.now().toString();
	}
}