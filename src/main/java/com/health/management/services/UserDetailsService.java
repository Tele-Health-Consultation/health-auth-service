package com.health.management.services;

import com.health.management.models.AuthUser;
import com.health.management.repositories.AuthUserRepository;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final AuthUserRepository authUserRepository;

    @Override
    @NonNull
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        Optional<AuthUser> authUser = authUserRepository.findByUsernameOrEmail(username);
        if (authUser.isEmpty()) throw new UsernameNotFoundException(username);
        return authUser.get();
    }
}
