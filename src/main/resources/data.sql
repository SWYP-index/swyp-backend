-- data.sql

-- =================================================================
-- 초기 마스터 데이터
-- =================================================================

-- Emotion (ID 1~20 고정)
INSERT INTO emotion (id, name, category) VALUES (1, '감동', 'POSITIVE') ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (2, '설렘', 'POSITIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (3, '유쾌한', 'POSITIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (4, '공감', 'POSITIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (5, '위로', 'POSITIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (6, '슬픔', 'NEGATIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (7, '분노', 'NEGATIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (8, '혼란', 'NEGATIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (9, '불쾌한', 'NEGATIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (10, '공포', 'NEGATIVE')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (11, '놀람', 'NEUTRAL')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (12, '당황한', 'NEUTRAL')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (13, '답답한', 'NEUTRAL')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (14, '아쉬운', 'NEUTRAL')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (15, '어색한', 'NEUTRAL')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (16, '깨달음', 'THOUGHT')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (17, '통찰', 'THOUGHT')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (18, '의문', 'THOUGHT')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (19, '영감', 'THOUGHT')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);
INSERT INTO emotion (id, name, category) VALUES (20, '성찰', 'THOUGHT')ON DUPLICATE KEY UPDATE name = VALUES(name), category = VALUES(category);


--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (1, '감동', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_gamdong.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (2, '설렘', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_seollem.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (3, '유쾌한', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_yukwaehan.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (4, '공감', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_gonggam.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (5, '위로', 'POSITIVE', 'YOUR_S3_BASE_URL/positive_wiro.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (6, '슬픔', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_seulpeum.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (7, '분노', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_bunno.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (8, '혼란', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_honlan.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (9, '불쾌한', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_bulkwaehan.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (10, '공포', 'NEGATIVE', 'YOUR_S3_BASE_URL/negative_gongpo.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (11, '놀람', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_nollam.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (12, '당황한', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_danghwanghan.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (13, '답답한', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_dapdaphan.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (14, '아쉬운', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_aswium.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (15, '어색한', 'NEUTRAL', 'YOUR_S3_BASE_URL/neutral_eosaekhan.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (16, '깨달음', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_ggaedar-eum.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (17, '통찰', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_tongchal.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (18, '의문', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_uimun.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (19, '영감', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_yeonggam.png');
--INSERT INTO emotion (id, name, category, icon_image_url) VALUES (20, '성찰', 'THOUGHT', 'YOUR_S3_BASE_URL/thought_seongchal.png');

