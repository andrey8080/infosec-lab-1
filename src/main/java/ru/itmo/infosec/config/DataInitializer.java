package ru.itmo.infosec.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import ru.itmo.infosec.service.UserService;

/**
 * Инициализация тестовых данных при запуске приложения
 */
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserService userService;

    @Override
    public void run(String... args) {
        try {
            // Создаем тестового пользователя
            userService.createUser("admin", "admin123", "admin@example.com");
            userService.createUser("user", "user123", "user@example.com");
            System.out.println("Test users created successfully!");
        } catch (IllegalArgumentException e) {
            System.out.println("Test users already exist");
        }
    }
}
