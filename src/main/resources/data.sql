-- data.sql

-- =================================================================
-- 초기 마스터 데이터
-- =================================================================

-- Emotion (ID 1~20 고정)
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (1, '감동', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_gamdong.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (2, '설렘', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_seollem.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (3, '유쾌한', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_yukwaehan.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (4, '공감', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_gonggam.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (5, '위로', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_wiro.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (6, '슬픔', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_seulpeum.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (7, '분노', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_bunno.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (8, '혼란', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_honlan.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (9, '불쾌한', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_bulkwaehan.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (10, '공포', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_gongpo.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (11, '놀람', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_nollam.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (12, '당황한', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_danghwanghan.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (13, '답답한', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_dapdaphan.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (14, '아쉬운', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_aswium.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (15, '어색한', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_eosaekhan.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (16, '깨달음', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_ggaedar-eum.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (17, '통찰', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_tongchal.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (18, '의문', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_uimun.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (19, '영감', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_yeonggam.png');
INSERT INTO emotion (id, name, category, icon_image_url) VALUES (20, '성찰', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_seongchal.png');


-- =================================================================
-- 테스트용 데이터
-- =================================================================

-- User (비밀번호: password)
INSERT INTO user (email, nickname, password, provider, created_at, updated_at) VALUES ('youngchan0510@gmail.com', '크러쉬', '$2a$10$2YPRchvddGE6YKy5gWq90uawtQBckKE2pU.m/cVIHVgqt3wg12PGq', 'LOCAL', NOW(), NOW());

-- Book
INSERT INTO book (isbn, title, author, description, publisher, cover_image_url, published_date, category, total_emotion_count, total_emotion_score_sum)
VALUES ('9788937460476', '데미안', '헤르만 헤세', '새는 알에서 나오려고 투쟁한다. 알은 세계이다. 태어나려는 자는 한 세계를 깨뜨려야 한다.', '민음사', 'https://image.aladin.co.kr/product/26/0/coversum/s742633278_2.jpg', '1919-01-01', '고전소설', 0, 0);
INSERT INTO book (isbn, title, author, description, publisher, cover_image_url, published_date, category, total_emotion_count, total_emotion_score_sum)
VALUES ('9791191136979', '이처럼 사소한 것들', '클레어 키건', '1985년 아일랜드의 작은 마을, 크리스마스를 앞둔 어느 날...', '다산책방', 'https://image.aladin.co.kr/product/31221/53/coversum/k392832962_1.jpg', '2023-04-10', '소설', 0, 0);

-- BookStats (모든 책에 대해 20가지 감정 통계 초기화)
INSERT INTO book_stats (book_id, emotion_id, emotion_count, emotion_score_sum, emotion_score_average, created_at, updated_at)
SELECT b.id, e.id, 0, 0, 0.0, NOW(), NOW()
FROM book b, emotion e;

-- Bookshelf (테스트유저가 '데미안'은 다 읽었고, '이처럼 사소한 것들'은 읽는 중)
INSERT INTO bookshelf (user_id, book_id, status, created_at, updated_at, finished_at, final_note)
VALUES (1, 1, 'FINISHED', NOW() - INTERVAL 10 DAY, NOW() - INTERVAL 1 DAY, NOW() - INTERVAL 1 DAY, '내 어린 시절의 필독서. 다시 읽어도 감동적이다.');
INSERT INTO bookshelf (user_id, book_id, status, created_at, updated_at)
VALUES (1, 2, 'READING', NOW() - INTERVAL 5 DAY, NOW() - INTERVAL 2 DAY);

-- PageRecord & RecordEmotion ('데미안'에 대한 기록)
-- 기록 1
INSERT INTO page_record (bookshelf_id, page, content, created_at) VALUES (1, 50, '알을 깨고 나오는 구절이 인상적이었다.', NOW() - INTERVAL 8 DAY);
SET @last_record_id = LAST_INSERT_ID();
INSERT INTO record_emotion (page_record_id, emotion_id, emotion_score) VALUES (@last_record_id, 16, 10); -- 깨달음 10점
INSERT INTO record_emotion (page_record_id, emotion_id, emotion_score) VALUES (@last_record_id, 1, 8);  -- 감동 8점

-- 기록 2 (완독 기록)
INSERT INTO page_record (bookshelf_id, page, content, created_at) VALUES (1, null, '완독 후 남기는 마지막 감상.', NOW() - INTERVAL 1 DAY);
SET @last_record_id = LAST_INSERT_ID();
INSERT INTO record_emotion (page_record_id, emotion_id, emotion_score) VALUES (@last_record_id, 13, 7); -- 아쉬움 7점

-- PageRecord & RecordEmotion ('이처럼 사소한 것들'에 대한 기록)
-- 기록 1
INSERT INTO page_record (bookshelf_id, page, content, created_at) VALUES (2, 106, '주인공의 선행이 따뜻하게 느껴졌다.', NOW() - INTERVAL 2 DAY);
SET @last_record_id = LAST_INSERT_ID();
INSERT INTO record_emotion (page_record_id, emotion_id, emotion_score) VALUES (@last_record_id, 5, 9); -- 위로 9점

-- 통계 데이터 업데이트 (위 기록들을 바탕으로)
-- '데미안' 통계 업데이트
UPDATE book_stats SET emotion_count=1, emotion_score_sum=10, emotion_score_average=10.0, updated_at=NOW() WHERE book_id=1 AND emotion_id=16;
UPDATE book_stats SET emotion_count=1, emotion_score_sum=8, emotion_score_average=8.0, updated_at=NOW() WHERE book_id=1 AND emotion_id=1;
UPDATE book_stats SET emotion_count=1, emotion_score_sum=7, emotion_score_average=7.0, updated_at=NOW() WHERE book_id=1 AND emotion_id=13;
UPDATE book SET total_emotion_count=3, total_emotion_score_sum=25, updated_at=NOW() WHERE id=1;

-- '이처럼 사소한 것들' 통계 업데이트
UPDATE book_stats SET emotion_count=1, emotion_score_sum=9, emotion_score_average=9.0, updated_at=NOW() WHERE book_id=2 AND emotion_id=5;
UPDATE book SET total_emotion_count=1, total_emotion_score_sum=9, updated_at=NOW() WHERE id=2;