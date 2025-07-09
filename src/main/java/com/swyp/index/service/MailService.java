package com.swyp.index.service;


import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Random;

@Slf4j
@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;

    //6자리 랜덤 인증번호 생성
    public String createAuthCode(){
        Random random = new Random();
        return String.valueOf(111111 + random.nextInt(888889));
    }


    //지정된 이메일 주소로 인증 메일을 발송하는 메서드
    public void sendAuthMail(String toEmail, String authCode){
        String subject = "[Index] 회원가입 인증번호 안내";
        String text = "Index 회원가입을 위한 인증번호는 <strong>" + authCode + "</strong> 입니다.";

        try{
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "utf-8");
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(text, true);
            mailSender.send(mimeMessage);
            log.info("인증 메일 발송 성공: {}", toEmail);
        } catch (MessagingException e){
            log.error("인증 메일 발송 실패: {}", toEmail, e);
            throw new RuntimeException("메일 발송에 실패했습니다.");
        }
    }
}
