# Лабораторная работа 1

## API Endpoints

### Публичные эндпоинты

#### 1. POST `/auth/login` - Аутентификация пользователя

**Описание:** Принимает логин и пароль, возвращает JWT токен.

**Запрос:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Ответ (успех):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "username": "admin",
  "message": "Authentication successful"
}
```

**Ответ (ошибка):**
```json
{
  "error": "Invalid username or password"
}
```

**Пример с curl:**
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

#### 2. POST `/auth/register` - Регистрация нового пользователя

**Описание:** Создает нового пользователя с хэшированным паролем.

**Запрос:**
```json
{
  "username": "newuser",
  "password": "secure123",
  "email": "newuser@example.com"
}
```

**Ответ:**
```json
{
  "message": "User registered successfully",
  "username": "newuser"
}
```

**Пример с curl:**
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"secure123","email":"newuser@example.com"}'
```

### Защищенные эндпоинты (требуют JWT токен)

#### 3. GET `/api/data` - Получение списка пользователей

**Описание:** Возвращает список всех пользователей. Доступен только аутентифицированным пользователям. Все данные санитизируются для защиты от XSS.

**Заголовки:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Ответ:**
```json
{
  "currentUser": "admin",
  "users": [
    {
      "id": "1",
      "username": "admin",
      "email": "admin@example.com",
      "createdAt": "2024-12-12T10:30:00"
    }
  ],
  "count": 1
}
```

**Пример с curl:**
```bash
curl -X GET http://localhost:8080/api/data \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 4. GET `/api/profile` - Получение профиля текущего пользователя

**Описание:** Возвращает информацию о текущем аутентифицированном пользователе.

**Заголовки:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Ответ:**
```json
{
  "id": "1",
  "username": "admin",
  "email": "admin@example.com",
  "createdAt": "2024-12-12T10:30:00"
}
```

#### 5. POST `/api/message` - Создание сообщения

**Описание:** Принимает сообщение от пользователя и демонстрирует защиту от XSS через санитизацию и экранирование HTML.

**Заголовки:**
```
Authorization: Bearer <JWT_TOKEN>
```

**Запрос:**
```json
{
  "message": "<script>alert('XSS')</script>Hello World"
}
```

**Ответ:**
```json
{
  "user": "admin",
  "originalMessage": "<script>alert('XSS')</script>Hello World",
  "sanitizedMessage": "Hello World",
  "escapedMessage": "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;&#x2F;script&gt;Hello World",
  "status": "Message processed successfully"
}
```

**Пример с curl:**
```bash
curl -X POST http://localhost:8080/api/message \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"<script>alert(\"XSS\")</script>Hello"}'
```

## Реализованные меры защиты

### 1. Защита от SQL-инъекций (SQLi)

**Реализация:**
- Использование Spring Data JPA и Hibernate ORM
- Все запросы к БД выполняются через параметризованные запросы (Prepared Statements)
- Отсутствие конкатенации строк при формировании SQL-запросов

```java
// UserRepository.java
@Query("SELECT u FROM User u WHERE u.username = :username")
Optional<User> findByUsernameCustom(@Param("username") String username);
```

### 2. Защита от XSS

**Реализация:**
- Использование OWASP Java HTML Sanitizer для очистки HTML
- Экранирование специальных символов перед отправкой данных клиенту
- Санитизация всех пользовательских данных в ответах API

```java
// XssSanitizer.java
public String sanitize(String input) {
    return POLICY.sanitize(input);
}

public String escapeHtml(String input) {
    return input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;");
}
```

### 3. Защита от Broken Authentication

**Реализация:**

#### a) JWT токены
- Генерация JWT токена при успешной аутентификации
- Токен содержит username и время истечения (24 часа)
- Подпись токена секретным ключом (HS256)

**Код:**
```java
// JwtUtil.java
public String generateToken(String username) {
    return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(getSignKey(), SignatureAlgorithm.HS256)
        .compact();
}
```

#### b) Middleware для проверки JWT
- Фильтр `JwtAuthenticationFilter` проверяет токен в каждом запросе
- Извлечение токена из заголовка `Authorization: Bearer <token>`
- Валидация токена и установка аутентификации в SecurityContext

**Код:**
```java
// JwtAuthenticationFilter.java
if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
    jwt = authorizationHeader.substring(7);
    username = jwtUtil.extractUsername(jwt);
    
    if (jwtUtil.validateToken(jwt, userDetails.getUsername())) {
        // Установка аутентификации
    }
}
```

#### c) Хэширование паролей
- Использование BCrypt для хэширования паролей
- BCrypt автоматически добавляет соль к каждому паролю
- Пароли никогда не хранятся в открытом виде

**Код:**
```java
// SecurityConfig.java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// UserService.java
user.setPassword(passwordEncoder.encode(password));
```

## Запросы

1. **Регистрация нового пользователя:**
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "test123",
    "email": "test@example.com"
  }'
```

1. **Аутентификация:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "test123"
  }' | jq -r '.token')

echo $TOKEN
```

3. **Получение данных:**
```bash
curl -X GET http://localhost:8080/api/data \
  -H "Authorization: Bearer $TOKEN"
```

4. **Получение профиля:**
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer $TOKEN"
```

5. **Отправка сообщения с XSS:**
```bash
curl -X POST http://localhost:8080/api/message \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "<script>alert(\"XSS Attack\")</script>Hello World"
  }'
```
