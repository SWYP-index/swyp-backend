package com.swyp.index.presentation.api.emotion;


import com.swyp.index.application.emotion.EmotionService;
import com.swyp.index.presentation.dto.emotion.EmotionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "감정 API", description = "감정 목록을 조회하는 API입니다.")
@RestController
@RequestMapping("/api/emotions")
@RequiredArgsConstructor
public class EmotionApi {

    private final EmotionService emotionService;

    @Operation(summary = "전체 감정 목록 조회", description = "선택할 수 있는 모든 감정의 목록을 반환합니다.")
    @GetMapping
    public ResponseEntity<List<EmotionResponse>> getAllEmotions() {
        return ResponseEntity.ok(emotionService.getAllEmotions());
    }
}
