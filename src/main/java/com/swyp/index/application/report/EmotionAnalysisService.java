package com.swyp.index.application.report;

import com.swyp.index.infrastructure.repository.RecordEmotionRepository;
import com.swyp.index.infrastructure.repository.UserEmotionStatProjection;
import com.swyp.index.presentation.dto.report.EmotionStatDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class EmotionAnalysisService {

    private final RecordEmotionRepository recordEmotionRepository;

    /**
     * 사용자가 특정 도서에 대해 느낀 감정의 비율(%)을 계산하여 반환한다.
     * - 감정별 점수 총합을 기반으로 전체 감정 점수 중 비중을 계산
     *
     * @param userId 사용자 ID
     * @param isbn 도서 ISBN
     * @return 감정별 비중 리스트
     */
    public List<EmotionStatDto> getBookEmotionStatsByIsbn(Long userId, String isbn){

        //1. 감정별 점수 총합 계산
        List<UserEmotionStatProjection> stats = recordEmotionRepository.findBookEmotionStatsByIsbn(userId, isbn);

        //2. 총 점수 계산(0이면 빈 결과 반환)
        int total = stats.stream()
                .mapToInt(UserEmotionStatProjection::getTotalScore)
                .sum();

        if (total == 0){
            return List.of();
        }

        //3. 감정별 비중 계산 및 최다 감정 찾기
        List<EmotionStatDto> result = new ArrayList<>();
        for (UserEmotionStatProjection s : stats){
            int percentage = Math.round((s.getTotalScore() * 100.0f) / total);
            result.add(new EmotionStatDto(s.getEmotionType(), percentage));
        }

        //4. 결과 반환
        return result;
    }
}
