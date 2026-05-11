package com.health.management.utils;

import com.health.management.configs.JwtProperties;
import com.health.management.models.AuthUser;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtils {

    private final JwtProperties jwtProperties;

    // ── Individual Claim Extractors ──────────────────────────────────

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractUserId(String token) {
        return extractAllClaims(token).get("userId", String.class);
    }

    public String extractUserRefId(String token) {
        return extractAllClaims(token).get("userRefId", String.class);
    }

    public String extractEmail(String token) {
        return extractAllClaims(token).get("email", String.class);
    }

    public String extractUserType(String token) {
        return extractAllClaims(token).get("userType", String.class);
    }

    public List<String> extractRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }

    public List<String> extractPermissions(String token) {
        return extractAllClaims(token).get("permissions", List.class);
    }

    public Instant extractExpiry(String token) {
        return extractAllClaims(token).getExpiration().toInstant();
    }

    public Instant extractIssuedAt(String token) {
        return extractAllClaims(token).getIssuedAt().toInstant();
    }

    // ── Token Parsing ────────────────────────────────────────────────

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch (ExpiredJwtException ex) {
            log.warn("JWT expired: {}", ex.getMessage());
            throw new JwtException(ex.getMessage());

        } catch (UnsupportedJwtException ex) {
            log.warn("JWT unsupported: {}", ex.getMessage());
            throw new JwtException(ex.getMessage());

        } catch (MalformedJwtException ex) {
            log.warn("JWT malformed: {}", ex.getMessage());
            throw new JwtException(ex.getMessage());

        } catch (SecurityException ex) {
            log.warn("JWT signature invalid: {}", ex.getMessage());
            throw new JwtException(ex.getMessage());

        } catch (IllegalArgumentException ex) {
            log.warn("JWT empty or null: {}", ex.getMessage());
            throw new JwtException(ex.getMessage());
        }
    }

    // ── Token Validation ─────────────────────────────────────────────

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = extractAllClaims(token);

            String username = claims.getSubject();
            String tokenType = claims.get("type", String.class);
            boolean isExpired = claims.getExpiration().before(Date.from(Instant.now()));

            return username.equals(userDetails.getUsername())
                    && !isExpired && "ACCESS".equals(tokenType);   // reject refresh tokens here

        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Access token validation failed: {}", ex.getMessage());
            return false;
        }
    }

    public boolean isRefreshTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);

            String tokenType = claims.get("type", String.class);
            boolean isExpired = claims.getExpiration().before(Date.from(Instant.now()));

            return !isExpired && "REFRESH".equals(tokenType);

        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Refresh token validation failed: {}", ex.getMessage());
            return false;
        }
    }

    // ── Token Generation ─────────────────────────────────────────────

    public String generateAccessToken(AuthUser user) {
        Map<String, Object> claims = buildClaims(user);
        return buildToken(claims, user.getUsername(),
                jwtProperties.getAccessTokenExpiry(), "ACCESS");
    }

    public String generateRefreshToken(AuthUser user) {
        return buildToken(new HashMap<>(), user.getUsername(),
                jwtProperties.getRefreshTokenExpiry(), "REFRESH");
    }

    // ── Signing Key ──────────────────────────────────────────────────

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);    // HS256 key
    }

    // ── Claims Builder ───────────────────────────────────────────────

    private Map<String, Object> buildClaims(AuthUser user) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("userId", user.getId().toString());
        claims.put("userRefId", user.getUserRefId().toString());
        claims.put("email", user.getEmail());
        claims.put("userType", user.getUserType().name());
        claims.put("roles", user.getRoles());
        claims.put("permissions", user.getPermissions());
        claims.put("mfaEnabled", user.isMfaEnabled());
        claims.put("emailVerified", user.isEmailVerified());

        return claims;
    }

    private String buildToken(Map<String, Object> extraClaims, String subject,
                              long expiry, String tokenType) {
        Instant now = Instant.now();

        return Jwts.builder()
                .claims(extraClaims)                            // custom claims first
                .subject(subject)                               // username
                .issuer(jwtProperties.getIssuer())              // who issued it
                .issuedAt(Date.from(now))                       // issued time
                .notBefore(Date.from(now))                      // valid from
                .expiration(Date.from(now.plusMillis(expiry)))  // expiry time
                .id(UUID.randomUUID().toString())               // unique JWT ID (jti)
                .claim("type", tokenType)                       // ACCESS or REFRESH
                .signWith(getSigningKey())                      // sign with HS256
                .compact();
    }

    // ── Bearer Token Extraction ──────────────────────────────────────

    public Optional<String> extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {
            return Optional.empty();
        }
        return Optional.of(authorizationHeader.substring(7));  // strip "Bearer "
    }

    // ── Refresh Token Hashing ────────────────────────────────────────
    // Store hash in DB — never raw refresh token

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException ex) {
            log.error("SHA-256 algorithm not found", ex);
            throw new RuntimeException("Token hashing failed", ex);
        }
    }

    public boolean matchesTokenHash(String rawToken, String storedHash) {
        return hashToken(rawToken).equals(storedHash);
    }

    // ── Utility ──────────────────────────────────────────────────────

    public boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token)
                    .getExpiration()
                    .before(Date.from(Instant.now()));
        } catch (JwtException ex) {
            return true;
        }
    }

    public long getAccessTokenExpiryMs() {
        return jwtProperties.getAccessTokenExpiry();
    }

    public long getRefreshTokenExpiryMs() {
        return jwtProperties.getRefreshTokenExpiry();
    }
}
