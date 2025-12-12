package ru.itmo.infosec.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO для успешных ответов
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SuccessResponse {

    private String message;
    private String username;
}
