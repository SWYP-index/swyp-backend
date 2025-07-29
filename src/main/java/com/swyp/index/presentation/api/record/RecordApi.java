package com.swyp.index.presentation.api.record;

import com.swyp.index.application.record.RecordService;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.global.exception.ErrorResponse;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.record.RecordCreateRequest;
import com.swyp.index.presentation.dto.record.RecordResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "기록 API", description = "독서 기록 관련 API입니다.")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/records")
public class RecordApi {

    private final RecordService recordService;

    @Operation(summary = "페이지 기록 생성", description = "특정 책에 대한 페이지와 코멘트를 기록합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "기록 생성 성공",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = RecordResponse.class))),
            @ApiResponse(responseCode = "400", description = "입력값 유효성 검증 실패",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "관련 리소스 없음 (예: 책장에 해당 책이 없음)",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = ErrorResponse.class)))
    })
    @PostMapping("/pages")
    public ResponseEntity<RecordResponse> createPageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody RecordCreateRequest request
            ){
        Long currentUserId = principal.getId();
        PageRecord saved = recordService.createPageRecord(currentUserId, request);
        return ResponseEntity.ok(RecordResponse.of(saved));
    }


}
