package com.swyp.index.presentation.dto.record;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Schema(description = "완독 기록 수정을 위한 요청 DTO")
public class CompletionRecordUpdateRequest {

    @Size(max = 1000, message = "내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "수정할 내용 (1000자 이내)", example = "주인공의 대사가 인상깊었다.", nullable = true)
    private String content;

    @Size(max = 1500, message = "내용은 1500자 이하로 입력해주세요.")
    @Schema(description = "수정할 내용 (1500자 이내)", example = "주인공의 대사가 인상깊었다.", nullable = true)
    private String finalNote;

    @Valid
    @Size(max = 5, message = "감정은 최대 5개까지 선택할 수 있습니다.")
    @Schema(description = "수정할 감정 목록 (최대 5개)")
    private List<EmotionDto> emotions;

}
