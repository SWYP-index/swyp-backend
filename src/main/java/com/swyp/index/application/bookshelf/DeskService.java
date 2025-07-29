package com.swyp.index.application.bookshelf;

import com.swyp.index.infrastructure.repository.DeskRepository;
import com.swyp.index.presentation.dto.bookshelf.DeskBookDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DeskService {
    private final DeskRepository deskRepository;

    public List<DeskBookDto> getReadingBooks(Long userId){
        return deskRepository.findReadingBooksByUserId(userId);
    }
}
