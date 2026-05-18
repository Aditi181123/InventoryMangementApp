package com.stockpro.gateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationManager authenticationManager;
    private final JwtSecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers("/auth/login", "/auth/register", "/auth/verify", "/auth/resend-verification").permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        .pathMatchers("/error").permitAll()
                        
                        // RBAC Rules
                        .pathMatchers(HttpMethod.POST, "/products/**").hasAnyRole("ADMIN", "MANAGER", "INVENTORY_MANAGER")
                        .pathMatchers(HttpMethod.PUT, "/products/**").hasAnyRole("ADMIN", "MANAGER", "INVENTORY_MANAGER")
                        .pathMatchers(HttpMethod.DELETE, "/products/**").hasAnyRole("ADMIN", "MANAGER", "INVENTORY_MANAGER")
                        
                        .pathMatchers("/warehouses/**").hasAnyRole("ADMIN", "MANAGER", "INVENTORY_MANAGER", "WAREHOUSE_STAFF")
                        .pathMatchers("/suppliers/**").hasAnyRole("ADMIN", "MANAGER", "OFFICER", "INVENTORY_MANAGER", "PURCHASE_OFFICER")
                        .pathMatchers("/purchase-orders/**").hasAnyRole("ADMIN", "OFFICER", "PURCHASE_OFFICER", "INVENTORY_MANAGER")
                        .pathMatchers("/reports/**").hasAnyRole("ADMIN", "MANAGER", "INVENTORY_MANAGER")
                        .pathMatchers("/auth/users/**").hasRole("ADMIN")
                        
                        .anyExchange().authenticated()
                )
                .build();
    }
}