package com.health.management.repositories;

import com.health.management.models.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.*;

public interface AuthUserRepository extends JpaRepository<AuthUser, UUID> {

    @Query("from AuthUser where username = :username or email = :username")
    Optional<AuthUser> findByUsernameOrEmail(@Param("username") String username);

    // Individual lookups
    Optional<AuthUser> findByUsername(String username);

    Optional<AuthUser> findByEmail(String email);

    Optional<AuthUser> findByUserRefId(UUID userRefId);

    // ── Existence Checks (for registration validation) ──────────

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    // ── Security / Token flows ──────────────────────────────────

    Optional<AuthUser> findByPasswordResetToken(String token);

    Optional<AuthUser> findByRefreshTokenHash(String refreshTokenHash);
}
