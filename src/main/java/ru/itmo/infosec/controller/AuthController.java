package ru.itmo.infosec.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import ru.itmo.infosec.dto.AuthRequest;
import ru.itmo.infosec.dto.AuthResponse;
import ru.itmo.infosec.security.JwtUtil;
import ru.itmo.infosec.service.UserService;

import java.util.HashMap;
import java.util.Map;

/**
 * Контроллер для аутентификации
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtUtil jwtUtil;

    /**
     * POST /auth/login - Аутентификация пользователя
     * Принимает логин и пароль, возвращает JWT токен
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest authRequest) {
        try {
            // Аутентификация через Spring Security
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(),
                            authRequest.getPassword()));

            // Загрузить пользователя
            final UserDetails userDetails = userService.loadUserByUsername(authRequest.getUsername());

            // Генерация JWT токена
            final String jwt = jwtUtil.generateToken(userDetails.getUsername());

            return ResponseEntity.ok(new AuthResponse(jwt, userDetails.getUsername()));

        } catch (BadCredentialsException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid username or password");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * POST /auth/register - Регистрация нового пользователя (дополнительный метод)
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            String password = request.get("password");
            String email = request.get("email");

            if (username == null || password == null || email == null) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Username, password and email are required");
                return ResponseEntity.badRequest().body(error);
            }

            userService.createUser(username, password, email);

            Map<String, String> response = new HashMap<>();
            response.put("message", "User registered successfully");
            response.put("username", username);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (IllegalArgumentException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }
}
