package com.stockpro.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import jakarta.mail.internet.MimeMessage;

import com.stockpro.auth.dto.CreateUserRequest;
import com.stockpro.auth.dto.UserResponse;
import com.stockpro.auth.entity.Role;
import com.stockpro.auth.entity.User;
import com.stockpro.common.exception.BadRequestException;
import com.stockpro.auth.repository.UserRepository;
import com.stockpro.auth.security.JwtUtil;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private RabbitTemplate rabbitTemplate;

    @Mock
    private MimeMessage mimeMessage;

    @InjectMocks
    private AuthServiceImpl authService;

    private CreateUserRequest createUserRequest;
    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "mailUsername", "test@stockpro.com");

        createUserRequest = CreateUserRequest.builder()
                .fullName("Test User")
                .email("test@example.com")
                .password("password")
                .role(Role.ADMIN)
                .build();

        user = User.builder()
                .userId(1L)
                .fullName("Test User")
                .email("test@example.com")
                .passwordHash("hashedPassword")
                .role(Role.ADMIN)
                .isActive(true)
                .isEmailVerified(false)
                .build();
    }

    @Test
    void createUser_WhenEmailExists_ShouldThrowBadRequestException() {
        // Arrange
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        // Act & Assert
        assertThatThrownBy(() -> authService.createUser(createUserRequest))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Email already exists");
    }

    @Test
    void createUser_WhenSuccess_ShouldReturnUserResponse() {
        // Arrange
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        doNothing().when(mailSender).send(any(MimeMessage.class));

        // Act
        UserResponse response = authService.createUser(createUserRequest);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getEmail()).isEqualTo(createUserRequest.getEmail());
        verify(userRepository).save(any(User.class));
        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    void getUserById_WhenUserExists_ShouldReturnUserResponse() {
        // Arrange
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        // Act
        UserResponse response = authService.getUserById(1L);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.getEmail()).isEqualTo(user.getEmail());
    }

    @Test
    void verifyEmail_WhenTokenValid_ShouldVerifyUser() {
        // Arrange
        user.setVerificationToken("token123");
        when(userRepository.findAll()).thenReturn(java.util.List.of(user));

        // Act
        authService.verifyEmail("token123");

        // Assert
        assertThat(user.getIsEmailVerified()).isTrue();
        assertThat(user.getVerificationToken()).isNull();
        verify(userRepository).save(user);
    }
}
