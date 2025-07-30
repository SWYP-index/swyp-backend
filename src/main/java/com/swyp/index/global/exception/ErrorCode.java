package com.swyp.index.global.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ErrorCode {

	// 400
	INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "입력 값이 올바르지 않습니다."),
	PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "비밀번호가 일치하지 않습니다."),
	INVALID_VERIFICATION_CODE(HttpStatus.BAD_REQUEST, "이메일 인증 코드가 일치하지 않습니다."),
	CANNOT_RECORD_FINISHED_BOOK(HttpStatus.BAD_REQUEST, "이미 완독한 책에는 기록을 추가할 수 없습니다."),
	INVALID_STATUS_UPDATE(HttpStatus.BAD_REQUEST, "유효하지 않은 상태 변경 요청입니다."),
	INVALID_DATE_PARAMETER(HttpStatus.BAD_REQUEST, "유효하지 않은 연도 또는 월입니다."),
	EMOTIONS_NOT_PROVIDED(HttpStatus.BAD_REQUEST, "하나 이상의 감정을 등록해야 합니다."),
	EMPTY_RECORD_DATA(HttpStatus.BAD_REQUEST, "기록할 내용 또는 감정이 없습니다."),
	PAGE_NUMBER_REQUIRED(HttpStatus.BAD_REQUEST, "읽는 중인 기록에는 페이지 번호가 필요합니다."),

	// 401
	UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "인증되지 않은 사용자입니다."),
	ACCESS_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "토큰이 만료되었습니다."),
	TOKEN_NOT_FOUND(HttpStatus.UNAUTHORIZED, "토큰이 존재하지 않습니다."),
	TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),

	// 403
	EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN, "이메일 인증이 완료되지 않았습니다."),
	FORBIDDEN_ACCESS(HttpStatus.FORBIDDEN, "해당 리소스에 접근할 권한이 없습니다."),

	// 404
	USER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."),
	BOOK_NOT_FOUND(HttpStatus.NOT_FOUND, "해당 책을 찾을 수 없습니다."),
	BOOKSHELF_NOT_FOUND(HttpStatus.NOT_FOUND, "책장에 해당 책이 존재하지 않습니다."),
	RECORD_NOT_FOUND(HttpStatus.NOT_FOUND, "해당 기록을 찾을 수 없습니다."),
	EMOTION_NOT_FOUND(HttpStatus.NOT_FOUND, "해당 감정을 찾을 수 없습니다."),

	// 409
	DUPLICATE_EMAIL(HttpStatus.CONFLICT, "이미 사용 중인 이메일입니다."),
	DUPLICATE_NICKNAME(HttpStatus.CONFLICT, "이미 사용 중인 닉네임입니다."),
	BOOKSHELF_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 책장에 추가된 책입니다."),

	// 500
	INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부에 오류가 발생했습니다.");

	private final HttpStatus httpStatus;
	private final String message;

	public int getStatusCode() {
		return httpStatus.value();
	}
}
