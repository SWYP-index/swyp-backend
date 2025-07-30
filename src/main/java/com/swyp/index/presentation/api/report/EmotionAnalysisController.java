package com.swyp.index.presentation.api.report;

import com.swyp.index.application.report.EmotionAnalysisService;
import com.swyp.index.global.security.CustomPrincipal;
import com.swyp.index.presentation.dto.report.EmotionStatDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/emotions")
@RequiredArgsConstructor
@Tag(name = "Emotion", description = "도서별 감정 분석 API")
public class EmotionAnalysisController {

    private final EmotionAnalysisService emotionAnalysisService;

    @GetMapping("/books/{isbn}")
    @Operation(summary = "도서 감정 비중 분석", description = "사용자가 특정 도서에 대해 기록한 감정 점수를 기반으로 감정 비중(%)을 반환합니다.")
    public ResponseEntity<List<EmotionStatDto>> getUserBookEmotionStats(
            @AuthenticationPrincipal CustomPrincipal principal,
            @PathVariable("isbn") String isbn
    ) {
        Long userId = principal.getId();
        List<EmotionStatDto> stats = emotionAnalysisService.getBookEmotionStatsByIsbn(userId, isbn);
        return ResponseEntity.ok(stats);
    }

}
