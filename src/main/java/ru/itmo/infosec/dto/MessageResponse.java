package ru.itmo.infosec.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO для ответа после обработки сообщения
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessageResponse {

    private String user;
    private String originalMessage;
    private String sanitizedMessage;
    private String escapedMessage;
    private String status;
}
