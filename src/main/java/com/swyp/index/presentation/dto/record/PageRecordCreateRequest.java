package com.swyp.index.presentation.dto.record;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
@Schema(description = "페이지 단위 독서 기록 생성 요청 DTO")
public class PageRecordCreateRequest {

    @NotBlank(message = "ISBN은 필수입니다.")
    @Schema(description = "도서 ISBN", example = "9791191114225", requiredMode = Schema.RequiredMode.REQUIRED)
    private String isbn;

    @Nullable
    @Schema(description = "기록하는 페이지 번호", example = "123", requiredMode = Schema.RequiredMode.NOT_REQUIRED,nullable = true)
    private Integer page;

    @Nullable
    @Size(max = 1000, message = "내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "인상 깊은 구절 및 느낀 점 (1000자 이내)", example = "주인공의 선택이 인상 깊었다.",requiredMode = Schema.RequiredMode.NOT_REQUIRED,nullable = true)
    private String content;

    @Valid
    @Size(max = 5, message = "감정은 최대 5개까지 선택 할 수 있습니다.")
    @Schema(description = "독서 기록에 대한 감정 목록 (1~5개)", requiredMode=Schema.RequiredMode.NOT_REQUIRED, nullable = true)
    private List<EmotionDto> emotions;

}