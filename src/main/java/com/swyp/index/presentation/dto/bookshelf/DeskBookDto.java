package com.swyp.index.presentation.dto.bookshelf;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
@Schema(description = "책상에 올라간 도서 정보")
public class DeskBookDto {
    @Schema(description = "도서 ID", example = "1")
    private Long bookId;

    @Schema(description = "도서 제목", example = "데미안")
    private String title;


    @Schema(description = "도서 저자", example = "헤르만 헤세")
    private String author;

    @Schema(description = "도서 표지 이미지", example = "https://image.aladin.co.kr/product/26/0/coversum/s742633278_2.jpg")
    private String coverImage;

    @Schema(description = "책상에 등록된 시점", example = "2025-07-25T16:00:00")
    private LocalDateTime createdAt; //status가 Reading으로 바뀐 시점(책상에 올라간 시점)
    //private Status status;
}
