package com.swyp.index.application.bookshelf;

import com.swyp.index.infrastructure.repository.DeskRepository;
import com.swyp.index.presentation.dto.bookshelf.BookshelfResponse;
import com.swyp.index.presentation.dto.bookshelf.DeskBookDto;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DeskService {
    private final DeskRepository deskRepository;

    @Transactional
    public List<DeskBookDto> getReadingBooks(Long userId) {
        return deskRepository.findReadingBooksByUserId(userId);
    }
}
