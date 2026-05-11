package com.health.management.filters;

import com.health.management.dto.ErrorDto;
import com.health.management.exceptions.JwtException;
import com.health.management.services.UserDetailsService;
import com.health.management.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtil;
    private final UserDetailsService userDetailsService;

    private static final List<String> PUBLIC_URLS = List.of("");

    // ── Skip filter for public endpoints ─────────────────────────────
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return PUBLIC_URLS.stream()
                .anyMatch(path::startsWith);
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Step 1 — Extract Authorization header
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Step 2 — Validate header format
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or malformed Authorization header | path: {}", request.getRequestURI());

            sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
                    "Authorization header missing or malformed", request.getRequestURI());

            return;  // stop filter chain — don't proceed
        }

        try {
            // Step 3 — Extract raw token
            String token = jwtUtil.extractTokenFromHeader(authHeader).orElseThrow(JwtException::new);

            // Step 4 — Extract username from token
            String username = jwtUtil.extractUsername(token);

            // Step 5 — Only authenticate if not already authenticated
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Step 6 — Load user from DB
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Step 7 — Validate token against user
                if (!jwtUtil.isAccessTokenValid(token, userDetails)) {
                    log.warn("Invalid JWT token for user: {} | path: {}",
                            username, request.getRequestURI());
                    sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
                            "Token is invalid", request.getRequestURI());
                    return;
                }

                // Step 8 — Check account status flags from UserDetails
                if (!userDetails.isEnabled()) {
                    sendErrorResponse(response, HttpStatus.FORBIDDEN,
                            "Account is disabled", request.getRequestURI());
                    return;
                }

                if (!userDetails.isAccountNonLocked()) {
                    sendErrorResponse(response, HttpStatus.FORBIDDEN,
                            "Account is locked", request.getRequestURI());
                    return;
                }

                if (!userDetails.isAccountNonExpired()) {
                    sendErrorResponse(response, HttpStatus.FORBIDDEN,
                            "Account has expired", request.getRequestURI());
                    return;
                }

                if (!userDetails.isCredentialsNonExpired()) {
                    sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
                            "Credentials have expired. Please change your password.",
                            request.getRequestURI());
                    return;
                }

                // Step 9 — Build authentication token
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,  // credentials null after auth
                                userDetails.getAuthorities());    // roles + permissions

                // Step 10 — Attach request details to auth token
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Step 11 — Set authentication in Security Context
                SecurityContextHolder.getContext().setAuthentication(authToken);

                // Step 12 — Enrich request with user context headers
                // (useful for downstream services / logging)
                enrichRequestWithUserContext(request, response, token, filterChain);
                return;
            }

            filterChain.doFilter(request, response);

        } catch (JwtException ex) {
            log.warn("Expired JWT | path: {}", request.getRequestURI());
            sendErrorResponse(response,
                    HttpStatus.UNAUTHORIZED,
                    "Token has expired/invalid",
                    request.getRequestURI());

        } catch (UsernameNotFoundException ex) {
            log.warn("User not found from token | path: {}", request.getRequestURI());
            sendErrorResponse(response,
                    HttpStatus.UNAUTHORIZED,
                    "User not found",
                    request.getRequestURI());

        } catch (Exception ex) {
            log.error("Unexpected error in JWT filter | path: {}",
                    request.getRequestURI(), ex);
            sendErrorResponse(response,
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "An unexpected error occurred",
                    request.getRequestURI());
        }
    }

    // ── Enrich Request with User Context ─────────────────────────────
    // Adds user info as request attributes for controllers/logging
    // Also forwards headers for downstream microservice calls
    private void enrichRequestWithUserContext(HttpServletRequest request,
                                              HttpServletResponse response,
                                              String token,
                                              FilterChain filterChain)
            throws ServletException, IOException {

        HttpServletRequest mutatedRequest = new HttpServletRequestWrapper(request) {
            @Override
            public String getHeader(String name) {
                // Inject user context headers downstream
                if ("X-User-Id".equals(name))
                    return jwtUtil.extractUserId(token);
                if ("X-User-Ref-Id".equals(name))
                    return jwtUtil.extractUserRefId(token);
                if ("X-User-Email".equals(name))
                    return jwtUtil.extractEmail(token);
                if ("X-User-Type".equals(name))
                    return jwtUtil.extractUserType(token);
                return super.getHeader(name);
            }
        };

        // Also set as request attributes for use in controllers
        request.setAttribute("userId",    jwtUtil.extractUserId(token));
        request.setAttribute("userRefId", jwtUtil.extractUserRefId(token));
        request.setAttribute("email",     jwtUtil.extractEmail(token));
        request.setAttribute("userType",  jwtUtil.extractUserType(token));

        filterChain.doFilter(mutatedRequest, response);
    }

    // ── Error Response Writer ────────────────────────────────────────
    // Can't use @RestControllerAdvice here — filter runs BEFORE controllers
    // Must write JSON response manually
    private void sendErrorResponse(HttpServletResponse response, HttpStatus status,
                                   String message, String path) throws IOException {

        ErrorDto errorResponse = ErrorDto.builder()
                .status(status)
                .message(message)
                .uriPath(path)
                .time(Instant.now())
                .build();

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(
                objectMapper.writeValueAsString(errorResponse)
        );
    }
}
