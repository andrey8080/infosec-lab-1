package ru.itmo.infosec.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.itmo.infosec.security.JwtAuthenticationFilter;
import ru.itmo.infosec.security.JwtUtil;

/**
 * Конфигурация Spring Security
 * Настройка защиты эндпоинтов и аутентификации через JWT
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Конфигурация цепочки фильтров безопасности
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter)
            throws Exception {
        http
                // CSRF защита не требуется для stateless REST API с JWT токенами
                // т.к. отсутствуют cookies-based сессии, которые подвержены CSRF атакам
                // JWT токены передаются в Authorization header, который не может быть
                // автоматически добавлен браузером при CSRF атаке
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/auth/**", "/api/**", "/h2-console/**"))

                // Настройка авторизации запросов
                .authorizeHttpRequests(auth -> auth
                        // Публичные эндпоинты (доступны без аутентификации)
                        .requestMatchers("/auth/**", "/h2-console/**").permitAll()

                        // Все остальные запросы требуют аутентификации
                        .anyRequest().authenticated())

                // Stateless сессии (не сохраняем состояние между запросами)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Добавляем JWT фильтр перед стандартным фильтром аутентификации
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // Настройка для H2 консоли (только для разработки!)
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

        return http.build();
    }

    /**
     * JWT Authentication Filter
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil,
            @Lazy UserDetailsService userDetailsService) {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
    }

    /**
     * Password Encoder - использует BCrypt для хэширования паролей
     * BCrypt автоматически добавляет соль и является одним из самых безопасных
     * алгоритмов
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Authentication Manager для обработки аутентификации
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Authentication Provider с использованием UserDetailsService и PasswordEncoder
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider(@Lazy UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}
