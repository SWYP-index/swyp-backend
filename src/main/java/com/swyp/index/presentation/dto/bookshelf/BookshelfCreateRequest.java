package com.swyp.index.presentation.dto.bookshelf;


import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

//어떤 책을 책상에 추가할지 알려주기 위한 dto
@Getter
@Setter
public class BookshelfCreateRequest {
    @NotBlank(message = "ISBN은 필수입니다.")
    private String isbn;
}
