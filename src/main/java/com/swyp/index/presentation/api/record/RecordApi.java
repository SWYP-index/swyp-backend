package com.swyp.index.presentation.api.record;

import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.application.bookshelf.RecordService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.record.CompletionRecordCreateRequest;
import com.swyp.index.presentation.dto.record.CompletionRecordResponse;
import com.swyp.index.presentation.dto.record.PageRecordCreateRequest;
import com.swyp.index.presentation.dto.record.PageRecordResponse;
//import com.swyp.index.presentation.dto.record.RecordResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "독서 기록 API", description = "페이지 기록 및 완독 처리를 담당하는 API")
@SecurityRequirement(name = "JWT Authentication")
@RestController
@RequestMapping("/api/records")
@RequiredArgsConstructor
public class RecordApi {

    private final RecordService recordService;
    // private final BookshelfService bookshelfService; // 현재 코드에서 미사용으로 주석 처리 또는 제거 가능

    /**
     * '읽는 중'인 책에 대한 페이지 기록을 추가합니다.
     */
    @Operation(summary = "페이지 기록 추가 (읽는 중)", description = "'읽는 중'인 책에 대한 페이지 기록을 추가합니다. 책이 '읽는 중' 상태일 때만 기록할 수 있습니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "페이지 기록 성공",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = PageRecordResponse.class))),
            @ApiResponse(responseCode = "400", description = "요청 데이터 유효성 검사 실패 (ex. 페이지 누락, 내용 글자 수 초과)"),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @ApiResponse(responseCode = "404", description = "해당 ISBN의 책을 책장에서 찾을 수 없거나 '읽는 중' 상태가 아님")
    })
    @PostMapping("/pages")
    public ResponseEntity<PageRecordResponse> createPageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody PageRecordCreateRequest request
    ) {
        return ResponseEntity.ok(recordService.createPageRecord(principal.getId(), request));
    }

    /**
     * 책을 '완독' 상태로 변경하고 최종 감상을 기록합니다.
     */
    @Operation(summary = "완독 기록 추가 (다 읽음)", description = "책을 '다 읽음' 상태로 변경하고 최종 감상평을 기록합니다. 이 API 호출 시 책의 상태가 '다 읽음'으로 변경됩니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "완독 기록 성공",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = CompletionRecordResponse.class))),
            @ApiResponse(responseCode = "400", description = "요청 데이터 유효성 검사 실패 (ex. 감정 누락)"),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자"),
            @ApiResponse(responseCode = "404", description = "해당 ISBN의 책을 책장에서 찾을 수 없음")
    })
    @PostMapping("/completion")
    public ResponseEntity<CompletionRecordResponse> createCompletionRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody CompletionRecordCreateRequest request
    ) {
        return ResponseEntity.ok(recordService.createCompletionRecord(principal.getId(), request));
    }
}