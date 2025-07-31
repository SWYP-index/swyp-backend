package com.swyp.index.presentation.dto.record;

import com.swyp.index.domain.bookshelf.ReadingStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
@Schema(description = "독서 기록 생성 요청 DTO")
public class RecordCreateRequest {

    @NotNull(message = "ISBN은 필수입니다.")
    @Schema(description = "기록할 책의 ISBN", example = "9788937460476")
    private String isbn;

    @NotNull(message = "독서 상태는 필수입니다.")
    @Schema(description = "독서 상태", example = "READING")
    private ReadingStatus status;

    @Schema(description = "기록할 페이지 ('읽는 중' 상태일 때 필수)", example = "106", nullable = true)
    private Integer page;

    @Size(max = 1000, message = "내용은 1000자 이하로 입력해주세요.")
    @Schema(description = "인상 깊은 구절 및 느낀 점 (1000자 이내)", example = "주인공의 선택이 인상 깊었다.")
    private String content;

    @Size(max = 1500, message = "종합 감상평은 1500자 이하로 입력해주세요.")
    @Schema(description = "종합 감상평 ('다 읽음' 상태일 때 사용, 1500자 이내)", example = "오랜만에 깊은 울림을 주는 책이었다.")
    private String finalNote;

    @Valid //내부 DTO의 유효성 검증을 위해 추가
    @NotEmpty(message = "감정은 최소 1개 이상 선택해야 합니다.")
    @Schema(description = "기록에 포함될 감정 및 점수 목록")
    private List<EmotionDto> emotions;

    @Getter
    @Setter
    @Schema(description = "감정 ID 및 점수 DTO")
    public static class EmotionDto {
        @NotNull
        @Schema(description = "감정의 고유 ID", example = "1")
        private Long emotionId;

        @Min(value = 1, message = "점수는 1 이상이어야 합니다.")
        @Max(value = 10, message = "점수는 10 이하이어야 합니다.")
        @Schema(description = "감정 점수 (1~10)", example = "8")
        private int score;
    }
}