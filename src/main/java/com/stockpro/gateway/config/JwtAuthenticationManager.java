package com.stockpro.gateway.config;

import com.stockpro.gateway.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();
        
        try {
            if (jwtUtil.validateToken(authToken)) {
                String username = jwtUtil.extractUsername(authToken);
                String role = jwtUtil.extractRole(authToken);
                List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role));
                
                return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
            }
        } catch (Exception e) {
            return Mono.empty();
        }
        return Mono.empty();
    }
}
