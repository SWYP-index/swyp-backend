package com.swyp.index.infrastructure.redis;

import java.time.Duration;

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
	@Bean
	public LettuceConnectionFactory redisConnectionFactory() {
		RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();

		config.setHostName("localhost");
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

	// @Bean
	// public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
	// 	RedisTemplate<String, String> template = new RedisTemplate<>();
	//
	// 	template.setConnectionFactory(connectionFactory);
	// 	template.setKeySerializer(new StringRedisSerializer());
	// 	template.setValueSerializer(new StringRedisSerializer());
	//
	// 	return template;
	// }
	//
	// @Bean
	// public RedisTemplate<String, List<String>> listRedisTemplate(RedisConnectionFactory connectionFactory) {
	// 	RedisTemplate<String, List<String>> template = new RedisTemplate<>();
	//
	// 	template.setConnectionFactory(connectionFactory);
	// 	template.setKeySerializer(new StringRedisSerializer());
	//
	// 	Jackson2JsonRedisSerializer<List> serializer = new Jackson2JsonRedisSerializer<>(List.class);
	//
	// 	template.setValueSerializer(serializer);
	// 	template.afterPropertiesSet();
	//
	// 	return template;
	// }
}
