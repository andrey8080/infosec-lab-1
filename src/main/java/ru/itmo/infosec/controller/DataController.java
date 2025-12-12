package ru.itmo.infosec.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import ru.itmo.infosec.model.User;
import ru.itmo.infosec.repository.UserRepository;
import ru.itmo.infosec.util.XssSanitizer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Контроллер для защищенных API эндпоинтов
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DataController {

    private final UserRepository userRepository;
    private final XssSanitizer xssSanitizer;

    /**
     * GET /api/data - Получение списка пользователей
     * Доступен только аутентифицированным пользователям
     * Данные санитизируются для защиты от XSS
     */
    @GetMapping("/data")
    public ResponseEntity<?> getData() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        List<User> users = userRepository.findAll();

        // Санитизация данных перед отправкой (защита от XSS)
        List<Map<String, String>> sanitizedUsers = users.stream()
                .map(user -> {
                    Map<String, String> userData = new HashMap<>();
                    userData.put("id", String.valueOf(user.getId()));
                    userData.put("username", xssSanitizer.sanitize(user.getUsername()));
                    userData.put("email", xssSanitizer.sanitize(user.getEmail()));
                    userData.put("createdAt", user.getCreatedAt() != null ? user.getCreatedAt().toString() : "");
                    return userData;
                })
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("currentUser", currentUsername);
        response.put("users", sanitizedUsers);
        response.put("count", sanitizedUsers.size());

        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/profile - Получение профиля текущего пользователя
     * Дополнительный защищенный эндпоинт
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        User user = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Map<String, String> profile = new HashMap<>();
        profile.put("id", String.valueOf(user.getId()));
        profile.put("username", xssSanitizer.sanitize(user.getUsername()));
        profile.put("email", xssSanitizer.sanitize(user.getEmail()));
        profile.put("createdAt", user.getCreatedAt() != null ? user.getCreatedAt().toString() : "");

        return ResponseEntity.ok(profile);
    }

    /**
     * POST /api/message - Создание сообщения с санитизацией
     * Третий эндпоинт - демонстрирует защиту от XSS при приеме пользовательских
     * данных
     */
    @PostMapping("/message")
    public ResponseEntity<?> createMessage(@RequestBody Map<String, String> request) {
        String rawMessage = request.get("message");

        if (rawMessage == null || rawMessage.trim().isEmpty()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Message cannot be empty");
            return ResponseEntity.badRequest().body(error);
        }

        // Санитизация входящего сообщения (защита от XSS)
        String sanitizedMessage = xssSanitizer.sanitize(rawMessage);
        String escapedMessage = xssSanitizer.escapeHtml(rawMessage);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        Map<String, String> response = new HashMap<>();
        response.put("user", currentUsername);
        response.put("originalMessage", rawMessage);
        response.put("sanitizedMessage", sanitizedMessage);
        response.put("escapedMessage", escapedMessage);
        response.put("status", "Message processed successfully");

        return ResponseEntity.ok(response);
    }
}
