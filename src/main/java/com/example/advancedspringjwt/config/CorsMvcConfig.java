package com.example.advancedspringjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        corsRegistry.addMapping("/**") //모든 컨트롤러 경로에 대해서
                .allowedOrigins("http://localhost:3000"); //프론트 서버 3000번 포트를 허용
    }
}
