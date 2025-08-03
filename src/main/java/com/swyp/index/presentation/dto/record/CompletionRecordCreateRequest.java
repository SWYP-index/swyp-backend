package com.swyp.index.presentation.dto.record;

import com.swyp.index.domain.bookshelf.ReadingStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
public class CompletionRecordCreateRequest {
    @NotBlank(message = "ISBN은 필수입니다.")
    private String isbn;

    @Size(max = 1000, message = "내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "인상 깊은 구절 및 느낀 점 (1000자 이내)", example = "주인공의 선택이 인상 깊었다.")
    private String content;

    @Size(max = 1500, message = "종합 감상평은 1500자 이하로 입력해주세요.")
    @Schema(description = "종합 감상평 ('다 읽음' 상태일 때 사용, 1500자 이내)", example = "오랜만에 깊은 울림을 주는 책이었다.")
    private String finalNote; // 한 줄 요약 필드 (선택적)

    @NotEmpty(message = "감정은 최소 1개 이상 선택해야 합니다.")
    private List<EmotionDto> emotions;
}