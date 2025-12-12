package ru.itmo.infosec.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO для сообщений об ошибках
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {

    private String error;
}
