package com.swyp.index.presentation.dto.record;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Schema(description = "페이지 기록 수정을 위한 요청 DTO")
public class PageRecordUpdateRequest {

    @Nullable
    @Schema(description = "수정할 페이지 번호", example = "90", nullable = true)
    private Integer page;

    @Nullable
    @Size(max=1000, message="내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "수정할 내용 (1000자 이내)", example = "주인공의 대사가 인상깊었다.", nullable = true)
    private String content;

    @Valid
    @Size(max = 5, message = "감정은 최대 5개까지 선택할 수 있습니다.")
    @Schema(description = "수정할 감정 목록 (최대 5개)")
    private List<EmotionDto> emotions;

}
