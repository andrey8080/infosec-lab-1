package ru.itmo.infosec.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.itmo.infosec.model.User;

import java.util.Optional;

/**
 * Репозиторий для работы с пользователями
 * Использует JPA для защиты от SQL-инъекций (параметризованные запросы)
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Поиск пользователя по username
     * JPA автоматически использует параметризованные запросы
     */
    Optional<User> findByUsername(String username);

    /**
     * Пример кастомного JPQL запроса с параметрами
     * 
     * @param username имя пользователя
     * @return Optional<User>
     */
    @Query("SELECT u FROM User u WHERE u.username = :username")
    Optional<User> findByUsernameCustom(@Param("username") String username);

    /**
     * Проверка существования пользователя
     */
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}
