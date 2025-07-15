package com.swyp.index.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    // 이전에 만들었던 테스트 페이지들 (참고용)
    @GetMapping("/test/auth")
    public String authTestPage() {
        return "auth-test";
    }

    @GetMapping("/test/jwt")
    public String jwtTestPage() {
        return "jwt-test";
    }

    /**
     * 지금까지 제공된 모든 API를 테스트할 수 있는
     * 최종 통합 테스트 페이지를 반환합니다.
     * @return all-in-one-auth-test.html 파일
     */
    @GetMapping("/test/all-in-one")
    public String allInOneAuthTestPage() {
        return "all-in-one-auth-test";
    }
}