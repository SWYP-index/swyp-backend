package com.swyp.index.presentation.api.record;

import com.swyp.index.application.record.RecordService;
import com.swyp.index.domain.bookshelf.PageRecord;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.record.RecordCreateRequest;
import com.swyp.index.presentation.dto.record.RecordResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/records")
public class RecordApi {

    private final RecordService recordService;

    @PostMapping("/pages")
    public ResponseEntity<RecordResponse> createPageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody RecordCreateRequest request
            ){
        Long currentUserId = principal.getId();
        PageRecord saved = recordService.createPageRecord(currentUserId, request);
        RecordResponse response = RecordResponse.of(saved);
        return ResponseEntity.ok(response);
    }


}
