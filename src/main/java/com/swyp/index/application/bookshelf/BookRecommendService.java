package com.swyp.index.application.bookshelf;

import com.swyp.index.application.book.BookQueryService;
import com.swyp.index.application.report.EmotionAnalysisService;
import com.swyp.index.domain.book.Book;
import com.swyp.index.global.exception.CustomException;
import com.swyp.index.global.exception.ErrorCode;
import com.swyp.index.infrastructure.repository.BookRepository;
import com.swyp.index.presentation.dto.book.BookDto;
import com.swyp.index.presentation.dto.bookshelf.RecommendedBookDto;
import com.swyp.index.presentation.dto.report.EmotionRankingResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class BookRecommendService {

    private final BookRepository bookRepository;
    private final BookQueryService bookQueryService;
    private final EmotionAnalysisService emotionAnalysisService;
    private final BookshelfService bookshelfService;

    public List<RecommendedBookDto> getRecommendBooksOnly(Long userId){
        List<String> readingIsbns = bookshelfService.getReadingIsbns(userId);
        int readingCount = readingIsbns.size();

        int maxRecommendCount = (readingCount >= 3) ? 2 : (5 - readingCount);
        if (maxRecommendCount <= 0) return List.of();


        List<EmotionRankingResponse> top3 = emotionAnalysisService.getTop3Emotions(userId);
        Set<String> exclude = new HashSet<>(readingIsbns);
        List<RecommendedBookDto> result = new ArrayList<>();


        if(readingCount >= 3){
            result.addAll(pickTopBooks(top3, 0, 1, exclude));
            result.addAll(pickTopBooks(top3, 1, 1, exclude));
        } else if (readingCount == 2) {
            result.addAll(pickTopBooks(top3, 0, 1, exclude));
            result.addAll(pickTopBooks(top3, 1, 1, exclude));
            result.addAll(pickTopBooks(top3, 2, 1, exclude));
        } else if (readingCount == 1) {
            result.addAll(pickTopBooks(top3, 0, 2, exclude));
            result.addAll(pickTopBooks(top3, 1, 1, exclude));
            result.addAll(pickTopBooks(top3, 2, 1, exclude));
        } else if (readingCount == 0) {
            // 책상 비어있으면 top1,2,3에서 총 5권까지
            result.addAll(pickTopBooks(top3, 0, 2, exclude));
            result.addAll(pickTopBooks(top3, 1, 2, exclude));
            result.addAll(pickTopBooks(top3, 2, 1, exclude));
        }

        return result.stream().limit(maxRecommendCount).toList();


    }

    private List<RecommendedBookDto> pickTopBooks(List<EmotionRankingResponse> top3, int index, int count, Set<String> exclude){
        if(index >= top3.size()) return List.of();

        String emotionName = top3.get(index).emotionName();
        List<BookDto> books = bookQueryService.getBooksByEmotion(emotionName, 1);

        List<RecommendedBookDto> result = new ArrayList<>();
        for (BookDto dto : books) {
            if(exclude.add(dto.getIsbn())){
                Book book = bookRepository.findByIsbn(dto.getIsbn())
                        .orElseThrow(() -> new CustomException(ErrorCode.BOOK_NOT_FOUND));
                result.add(RecommendedBookDto.of(emotionName, book));
                if(result.size() == count) break;
            }
        }
        return result;
    }


}
