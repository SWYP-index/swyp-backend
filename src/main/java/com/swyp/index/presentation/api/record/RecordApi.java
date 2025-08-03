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
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "독서 기록 API", description = "페이지 기록 및 완독 처리를 담당하는 API")
@RestController
@RequestMapping("/api/records")
@RequiredArgsConstructor
public class RecordApi {

    private final RecordService recordService;
    private final BookshelfService bookshelfService;

    /**
     * '읽는 중'인 책에 대한 페이지 기록을 추가합니다.
     */
    @Operation(summary = "페이지 기록 추가 (읽는 중)")
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
    @Operation(summary = "완독 기록 추가 (다 읽음)")
    @PostMapping("/completion")
    public ResponseEntity<CompletionRecordResponse> createCompletionRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody CompletionRecordCreateRequest request
    ) {
        return ResponseEntity.ok(bookshelfService.finishBookWithNote(principal.getId(), request));
    }
}