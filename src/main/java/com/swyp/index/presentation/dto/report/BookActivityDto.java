package com.swyp.index.presentation.dto.report;

import com.swyp.index.domain.bookshelf.Bookshelf;
import com.swyp.index.domain.bookshelf.ReadingStatus;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Data
public class BookActivityDto {
    private String isbn;
    private String title;
    private String coverImage;
    private ReadingStatus status;
    private boolean isStartDate = false;
    private boolean isFinishDate = false;
    private Set<Long> emotionsId = new HashSet<>();

    public static BookActivityDto from (Bookshelf bookshelf){
        BookActivityDto dto = new BookActivityDto();
        dto.setIsbn(bookshelf.getBook().getIsbn());
        dto.setTitle(bookshelf.getBook().getBookInfo().getTitle());
        dto.setCoverImage(bookshelf.getBook().getBookInfo().getCoverImageUrl());
        dto.setStatus(bookshelf.getStatus());
        return dto;
    }
}
