package com.swyp.index.presentation.dto.wishlist;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "찜 목록 추가 요청 DTO")
public class WishlistRequest {

    @NotBlank(message = "ISBN은 필수입니다.")
    @Schema(description = "찜할 도서의 ISBN", example = "9791191891234", requiredMode = Schema.RequiredMode.REQUIRED)
    private String isbn;
}