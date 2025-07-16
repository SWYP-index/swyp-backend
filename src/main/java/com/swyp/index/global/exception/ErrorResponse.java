package com.swyp.index.global.exception;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class ErrorResponse {
	private int status;
	private String message;
	private String timestamp;

	public ErrorResponse(int status, String message) {
		this.status = status;
		this.message = message;
		this.timestamp = java.time.OffsetDateTime.now().toString();
	}
}