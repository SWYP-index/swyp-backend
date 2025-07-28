package com.swyp.index.presentation.dto.record;


import com.swyp.index.domain.bookshelf.ReadingStatus;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.util.List;


@Getter
@Setter
public class RecordCreateRequest {

    @NotNull(message = "ISBN은 필수입니다.")
    private String isbn;

    @NotNull(message = "독서 상태는 필수입니다.")
    private ReadingStatus status;

    private int page;
    private String content;

    @NotEmpty(message = "감정은 최소 1개 이상 선택해야 합니다.")
    private List<EmotionDto> emotions;

    /**
     * 감정 ID와 점수를 함께 받기 위한 내부 DTO.
     */
    @Getter
    @Setter
    public static class EmotionDto {
        @NotNull
        private Long emotionId; // 어떤 감정인지
        private int score;      // 몇 점인지
    }
}
