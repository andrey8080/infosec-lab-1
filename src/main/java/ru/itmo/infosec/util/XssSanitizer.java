package ru.itmo.infosec.util;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Component;

/**
 * Утилита для санитизации пользовательского ввода (защита от XSS)
 */
@Component
public class XssSanitizer {

    private static final PolicyFactory POLICY = new HtmlPolicyBuilder()
            .toFactory();

    /**
     * Очистить строку от потенциально опасного HTML/JavaScript кода
     */
    public String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return POLICY.sanitize(input);
    }

    /**
     * Экранировать HTML символы
     */
    public String escapeHtml(String input) {
        if (input == null) {
            return null;
        }
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }
}
