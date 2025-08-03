package com.swyp.index.presentation.dto.record;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
public class PageRecordCreateRequest {

    @NotBlank(message = "ISBN은 필수입니다.")
    private String isbn;

    @NotNull(message = "페이지는 필수입니다.")
    private Integer page;

    @Size(max = 1000, message = "내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "인상 깊은 구절 및 느낀 점 (1000자 이내)", example = "주인공의 선택이 인상 깊었다.")
    private String content;

    @NotEmpty(message = "감정은 최소 1개 이상 선택해야 합니다.")
    private List<EmotionDto> emotions;

}