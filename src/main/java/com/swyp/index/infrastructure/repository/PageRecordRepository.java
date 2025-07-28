package com.swyp.index.infrastructure.repository;

import com.swyp.index.domain.pagerecord.PageRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PageRecordRepository extends JpaRepository<PageRecord, Long> {
}
