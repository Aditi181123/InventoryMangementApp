package com.stockpro.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.stockpro.auth.dto.LoginRequest;
import com.stockpro.auth.dto.JwtResponse;
import com.stockpro.auth.dto.UserResponse;
import com.stockpro.auth.service.AuthService;
import com.stockpro.auth.security.CustomUserDetailsService;
import com.stockpro.auth.security.JwtUtil;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false) // Disable security filters for simple controller testing
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private CustomUserDetailsService userDetailsService;

    @MockBean
    private JwtUtil jwtUtil;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void login_ShouldReturnJwtResponse() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest("test@example.com", "password");
        JwtResponse jwtResponse = JwtResponse.builder()
                .token("jwt.token.here")
                .email("test@example.com")
                .userId(1L)
                .role("ADMIN")
                .build();

        when(authService.login(any(LoginRequest.class))).thenReturn(jwtResponse);

        // Act & Assert
        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.token").value("jwt.token.here"));
    }

    @Test
    void verifyEmail_ShouldReturnSuccess() throws Exception {
        // Act & Assert
        mockMvc.perform(get("/auth/verify")
                .param("token", "token123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified successfully"));
    }
}
