package com.swyp.index.presentation.dto.record;

import com.swyp.index.domain.bookshelf.ReadingStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
@Schema(description = "독서 기록 (완독) 생성 요청 DTO")
public class CompletionRecordCreateRequest {

    @NotBlank(message = "ISBN은 필수입니다.")
    @Schema(description = "도서 ISBN", example = "9791191114225", requiredMode = Schema.RequiredMode.REQUIRED)
    private String isbn;

    @Nullable
    @Size(max = 1000, message = "내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "인상 깊은 구절 및 느낀 점 (1000자 이내)", example = "주인공의 선택이 인상 깊었다.", requiredMode=Schema.RequiredMode.NOT_REQUIRED,nullable = true)
    private String content;

    @Nullable
    @Size(max = 1500, message = "종합 감상평은 1500자 이하로 입력해주세요.")
    @Schema(description = "종합 감상평 (1500자 이내)", example = "오랜만에 깊은 울림을 주는 책이었다.", requiredMode=Schema.RequiredMode.NOT_REQUIRED,nullable = true)
    private String finalNote;

    @NotEmpty(message = "감정은 최소 1개 이상 선택해야 합니다.")
    @Size(max = 5, message = "감정은 최대 5개까지 선택 할 수 있습니다.")
    @Schema(description = "독서 기록에 대한 감정 목록 (1~5개)", requiredMode=Schema.RequiredMode.REQUIRED)
    private List<EmotionDto> emotions;
}