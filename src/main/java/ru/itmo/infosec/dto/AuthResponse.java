package ru.itmo.infosec.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO для ответа с JWT токеном
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String username;
    private String message;

    public AuthResponse(String token, String username) {
        this.token = token;
        this.username = username;
        this.message = "Authentication successful";
    }
}
