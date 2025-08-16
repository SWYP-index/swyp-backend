package com.swyp.index.presentation.api.record;

import com.swyp.index.application.bookshelf.BookshelfService;
import com.swyp.index.application.bookshelf.RecordService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.record.*;
//import com.swyp.index.presentation.dto.record.RecordResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
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

    /**
     * 페이지 기록을 단건 조회합니다.
     */
    @Operation(summary = "페이지 기록 상세 조회")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공"),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음"),
            @ApiResponse(responseCode = "404", description = "기록을 찾을 수 없음")
    })
    @GetMapping("/pages/{recordId}")
    public ResponseEntity<PageRecordResponse> getPageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "조회할 기록의 ID") @PathVariable Long recordId
    ){
        PageRecordResponse response = recordService.getPageRecord(principal.getId(), recordId);
        return ResponseEntity.ok(response);
    }

    /**
     * 페이지 기록을 수정합니다.
     */
    @Operation(summary = "페이지 기록 수정")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "수정 성공"),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음"),
            @ApiResponse(responseCode = "404", description = "기록을 찾을 수 없음")
    })
    @PutMapping("/pages/{recordId}")
    public ResponseEntity<Void> updatePageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "수정할 기록의 ID") @PathVariable Long recordId,
            @Valid @RequestBody PageRecordUpdateRequest request
    ) {
        recordService.updatePageRecord(principal.getId(), recordId, request);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "페이지 기록 삭제")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "삭제 성공"),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음"),
            @ApiResponse(responseCode = "404", description = "기록을 찾을 수 없음")
    })
    @DeleteMapping("/pages/{recordId}")
    public ResponseEntity<Void> deletePageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "삭제할 기록의 ID") @PathVariable Long recordId
    ) {
        recordService.deletePageRecord(principal.getId(), recordId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "완독 기록 상세 조회")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "조회 성공"),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음"),
            @ApiResponse(responseCode = "404", description = "책장 또는 완독 기록을 찾을 수 없음")
    })
    @GetMapping("/completion/{bookshelfId}")
    public ResponseEntity<CompletionRecordResponse> getCompletionRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "조회할 책장의 ID") @PathVariable Long bookshelfId
    ) {
        CompletionRecordResponse response = recordService.getCompletionRecord(principal.getId(), bookshelfId);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "완독 기록 수정")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "수정 성공"),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음"),
            @ApiResponse(responseCode = "404", description = "책장 또는 완독 기록을 찾을 수 없음")
    })
    @PutMapping("/completion/{bookshelfId}")
    public ResponseEntity<Void> updateCompletionRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "수정할 책장의 ID") @PathVariable Long bookshelfId,
            @Valid @RequestBody CompletionRecordUpdateRequest request
    ) {
        recordService.updateCompletionRecord(principal.getId(), bookshelfId, request);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "완독 기록 삭제 (완독 취소)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "삭제(완독 취소) 성공"),
            @ApiResponse(responseCode = "403", description = "접근 권한 없음"),
            @ApiResponse(responseCode = "404", description = "책장 또는 완독 기록을 찾을 수 없음")
    })
    @DeleteMapping("/completion/{bookshelfId}")
    public ResponseEntity<Void> deleteCompletionRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Parameter(description = "완독을 취소할 책장의 ID") @PathVariable Long bookshelfId
    ) {
        recordService.deleteCompletionRecord(principal.getId(), bookshelfId);
        return ResponseEntity.noContent().build();
    }

}