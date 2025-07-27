package com.swyp.index.infrastructure.redis;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

	@Value("${spring.redis.host}")
	private String redisHost;

	@Bean
	public LettuceConnectionFactory redisConnectionFactory() {
		RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();

		config.setHostName(redisHost);
		config.setPort(6379);

		LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
			.commandTimeout(Duration.ofSeconds(5))
			.build();

		return new LettuceConnectionFactory(config, clientConfig);
	}

	@Bean
	public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
		RedisTemplate<String, Object> template = new RedisTemplate<>();
		template.setConnectionFactory(connectionFactory);

		// key serializer (String)
		template.setKeySerializer(new StringRedisSerializer());
		template.setHashKeySerializer(new StringRedisSerializer());

		// value serializer (JSON)
		Jackson2JsonRedisSerializer<Object> serializer = new Jackson2JsonRedisSerializer<>(Object.class);
		template.setValueSerializer(serializer);
		template.setHashValueSerializer(serializer);

		template.afterPropertiesSet();

		return template;
	}
}
