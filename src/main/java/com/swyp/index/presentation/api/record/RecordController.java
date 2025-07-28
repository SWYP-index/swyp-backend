package com.swyp.index.presentation.api.record;

import com.swyp.index.application.record.RecordService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.record.RecordCreateRequestDto;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/records")
public class RecordController {

    private final RecordService recordService;

    @PostMapping("/pages")
    public ResponseEntity<Void> createPageRecord(
            @AuthenticationPrincipal CustomPrincipal principal,
            @Valid @RequestBody RecordCreateRequestDto requestDto
            ){
        Long currentUserId = principal.getId();
        recordService.createPageRecord(currentUserId, requestDto);
        return ResponseEntity.ok().build();
    }


}
