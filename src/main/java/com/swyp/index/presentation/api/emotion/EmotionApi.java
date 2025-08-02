package com.swyp.index.presentation.api.emotion;


import com.swyp.index.application.emotion.EmotionService;
import com.swyp.index.domain.emotion.EmotionCategory;
import com.swyp.index.presentation.dto.emotion.EmotionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "감정 API", description = "감정 목록을 조회하는 API입니다.")
@RestController
@RequestMapping("/api/emotions")
@RequiredArgsConstructor
public class EmotionApi {

    private final EmotionService emotionService;

    @Operation(
            summary = "전체 감정 목록 조회",
            description = "EmotionType Enum에 정의된 모든 감정 정보를 반환합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "전체 감정 목록 조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = EmotionResponse.class))
                    )
            )
    })
    @GetMapping
    public ResponseEntity<List<EmotionResponse>> getAllEmotions() {
        return ResponseEntity.ok(emotionService.getAllEmotions());
    }


    @Operation(
            summary = "단일 감정 조회",
            description = "ID와 카테고리를 이용해 특정 감정 정보를 조회합니다. ID가 0이면 기본 아이콘을 반환합니다."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "단일 감정 조회 성공",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = EmotionResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "잘못된 요청 (유효하지 않은 ID 혹은 파라미터)",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    description = "에러 응답 형식",
                                    example = "{\"timestamp\":\"2025-08-02T12:34:56.789Z\",\"status\":400,\"error\":\"Bad Request\",\"message\":\"Invalid emotion ID: 999\",\"path\":\"/api/emotions/999\"}"
                            )
                    )
            )
    })
    @GetMapping("/{id}")
    public ResponseEntity<EmotionResponse> getEmotion(
            @Parameter(
                    in = ParameterIn.PATH,
                    name = "id",
                    description = "조회할 감정의 고유 ID (0이면 기본 아이콘)",
                    required = true,
                    schema = @Schema(type = "integer", format = "int64", example = "0")
            )
            @PathVariable Long id,
            @Parameter(
                    in = ParameterIn.QUERY,
                    name = "category",
                    description = "ID가 0일 때 적용할 감정 카테고리",
                    required = true,
                    schema = @Schema(implementation = EmotionCategory.class, example = "POSITIVE")
            )
            @RequestParam EmotionCategory category
    ) {
        return ResponseEntity.ok(
                emotionService.getEmotionById(id, category)
        );
    }
}
