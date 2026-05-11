package com.health.management.models;

import com.health.management.enums.AccountStatus;
import com.health.management.enums.MfaType;
import com.health.management.enums.UserType;
import jakarta.persistence.*;
import lombok.*;
import org.jspecify.annotations.NonNull;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@Entity
@Table(name = "tbl_auth_users", indexes = {
        @Index(name = "idx_username", columnList = "username", unique = true),
        @Index(name = "idx_email", columnList = "email", unique = true),
        @Index(name = "idx_user_ref_id", columnList = "user_ref_id", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
public class AuthUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // ── The ONLY link to User Service ──────────────────────────────
    @Column(name = "user_ref_id", nullable = false, unique = true, updatable = false)
    private UUID userRefId;           // mirrors the PK in user-service DB
    // ──────────────────────────────────────────────────────────────

    // ── Core Login Identifiers ─────────────────────────────────────
    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false, unique = true, length = 100)
    private String email;             // needed for password reset / OTP flows

    @Column(nullable = false)
    private String password;          // bcrypt hash

    // ── Authorization ──────────────────────────────────────────────
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserType userType;        // DOCTOR, PATIENT, CLINIC etc.

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tbl_auth_user_roles",
            joinColumns = @JoinColumn(name = "auth_user_id"))
    @Column(name = "roles")
    private Set<String> roles = new HashSet<>();          // ROLE_USER, ROLE_ADMIN

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "tbl_auth_user_permissions",
            joinColumns = @JoinColumn(name = "auth_user_id"))
    @Column(name = "permissions")
    private Set<String> permissions = new HashSet<>();    // fine-grained permissions

    // ── Account State Machine ──────────────────────────────────────
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccountStatus accountStatus;  // ACTIVE, INACTIVE, SUSPENDED, DELETED, etc

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private boolean accountNonExpired = true;

    @Column(nullable = false)
    private boolean accountNonLocked = true;

    @Column(nullable = false)
    private boolean credentialsNonExpired = true;

    // ── Email / Phone Verification ─────────────────────────────────
    @Column(nullable = false)
    private boolean emailVerified = false;

    @Column(nullable = false)
    private boolean phoneVerified = false;

    // ── Security & Brute-Force Protection ─────────────────────────
    @Column(nullable = false)
    private int failedLoginAttempts = 0;

    @Column
    private Instant lockedUntil;            // temporary lockout expiry

    @Column
    private Instant lastLoginAt;

    @Column(length = 45)
    private String lastLoginIp;                   // IPv4 / IPv6

    // ── Password Management ────────────────────────────────────────
    @Column
    private Instant passwordChangedAt;

    @Column
    private String passwordResetToken;            // hashed reset token

    @Column
    private Instant passwordResetTokenExpiry;

    @Column(nullable = false)
    private boolean forcePasswordChange = false;  // admin-triggered

    // ── MFA ───────────────────────────────────────────────────────
    @Column(nullable = false)
    private boolean mfaEnabled = false;

    @Enumerated(EnumType.STRING)
    @Column
    private MfaType mfaType;                      // TOTP, SMS, EMAIL

    @Column
    private String mfaSecret;                     // encrypted TOTP secret

    // ── Token Management ──────────────────────────────────────────
    @Column
    private String refreshTokenHash;              // store hash, never raw token

    @Column
    private Instant refreshTokenExpiry;

    @Column
    private UUID tokenFamily;                     // refresh token rotation family

    // ── Audit ──────────────────────────────────────────────────────
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private Instant updatedAt;

    @Column(updatable = false, length = 50)
    private String createdBy;

    @Column(length = 50)
    private String updatedBy;

    @Version
    private Long version;                         // optimistic locking

    @Override
    @NonNull
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = new HashSet<>();

        roles.stream()
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);

        permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);

        return Collections.unmodifiableSet(authorities);
    }

    @Override
    public boolean isEnabled() {
        return accountStatus == AccountStatus.ACTIVE && enabled;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked &&
                (lockedUntil == null || lockedUntil.isBefore(Instant.now()));
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // force re-login if password not changed in 90 days
        return credentialsNonExpired &&
                passwordChangedAt != null &&
                passwordChangedAt.isAfter(Instant.now().minus(90, ChronoUnit.DAYS));
    }
}
