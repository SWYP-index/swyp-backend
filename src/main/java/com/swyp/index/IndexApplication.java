package com.swyp.index;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class IndexApplication {

	public static void main(String[] args) {
		Dotenv.configure().systemProperties().load();
		SpringApplication.run(IndexApplication.class, args);
	}

}
