package com.swyp.index.presentation.dto.book;

import java.time.LocalDate;
import java.util.List;

import com.swyp.index.domain.book.Book;
import com.swyp.index.domain.book.BookInfo;
import com.swyp.index.domain.book.BookStats;
import com.swyp.index.domain.emotion.EmotionType;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@Builder
@AllArgsConstructor
@Schema(description = "책 상세 정보 응답 DTO")
public class BookDto {

	@Schema(description = "ISBN", example = "9791191136979")
	private String isbn;

	@Schema(description = "제목", example = "이처럼 사소한 것들")
	private String title;

	@Schema(description = "저자", example = "클레어 키건")
	private String author;

	@Schema(description = "표지 이미지 URL", example = "https://image.aladin.co.kr/product/31221/53/coversum/k392832962_1.jpg")
	private String coverImageUrl;

	@Schema(description = "출판일", example = "2023-04-10")
	private LocalDate publishedDate;

	@Schema(description = "책 소개", example = "1985년 아일랜드의 작은 마을, 크리스마스를 앞둔 어느 날...")
	private String description;

	@Schema(description = "출판사", example = "다산책방")
	private String publisher;

	@Schema(description = "카테고리/장르", example = "소설")
	private String category;

	@Schema(description = "이 책에 남긴 총 감정 기록 수", example = "42")
	private Long totalEmotionCount;

	@Schema(description = "책 통계 정보 리스트")
	private List<BookEmotionDto> emotions;

	public record BookEmotionDto(Long id, String name, Long scoreSum, double percentage) {
	}

	public static BookDto from(Book book, List<BookStats> bookStats) {
		BookInfo info = book.getBookInfo();

		List<BookEmotionDto> bookEmotionDtos = mapBookStatsToDtos(book.getTotalEmotionScoreSum(), bookStats);

		return BookDto.builder()
			.isbn(book.getIsbn())
			.title(info.getTitle())
			.author(info.getAuthor())
			.coverImageUrl(info.getCoverImageUrl())
			.publishedDate(info.getPublishedDate())
			.description(info.getDescription())
			.publisher(info.getPublisher())
			.category(info.getCategory())
			.totalEmotionCount(book.getTotalEmotionCount())
			.emotions(bookEmotionDtos)
			.build();
	}

	private static List<BookEmotionDto> mapBookStatsToDtos(Long totalSum, List<BookStats> bookStats) {
		return bookStats.stream().map(bs -> {
			String emotionName = EmotionType.getNameById(bs.getEmotionId());
			long scoreSum = bs.getEmotionScoreSum();
			double percentage = calculatePercentage(scoreSum, totalSum);

			return new BookEmotionDto(bs.getEmotionId(), emotionName, bs.getEmotionScoreSum(), percentage);
		}).toList();
	}

	private static double calculatePercentage(long part, Long total) {
		if (total == null || total <= 0) {
			return 0.0;
		}

		double raw = (double)part / total * 100;

		return Math.round(raw * 100) / 100.0;
	}
}
