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
import ru.itmo.infosec.dto.RegisterRequest;
import ru.itmo.infosec.dto.SuccessResponse;
import ru.itmo.infosec.dto.ErrorResponse;
import ru.itmo.infosec.security.JwtUtil;
import ru.itmo.infosec.service.UserService;

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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Invalid username or password"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Authentication failed: " + e.getMessage()));
        }
    }

    /**
     * POST /auth/register - Регистрация нового пользователя (дополнительный метод)
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            userService.createUser(request.getUsername(), request.getPassword(), request.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new SuccessResponse("User registered successfully", request.getUsername()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ErrorResponse(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Registration failed: " + e.getMessage()));
        }
    }
}
