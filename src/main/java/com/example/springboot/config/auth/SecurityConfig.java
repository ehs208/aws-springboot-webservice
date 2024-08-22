package com.example.springboot.config.auth;

import com.example.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // CSRF 보호 비활성화
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())  // 동일 출처에서만 프레임 허용
                )
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/", "/css/**", "/images/**", "/js/**", "/h2-console/**", "/profile").permitAll()  // 특정 경로 허용
                        .requestMatchers("/api/v1/**").hasRole(Role.USER.name())  // USER 롤이 있는 사용자만 접근 가능  // USER 롤이 있는 사용자만 접근 가능
                        .anyRequest().authenticated()  // 그 외의 모든 요청은 인증 필요
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")  // 로그아웃 성공 후 리다이렉트 경로
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                .userService(customOAuth2UserService)  // 커스텀 OAuth2 사용자 서비스 설정
                        )
                );

        return http.build();
    }
}
