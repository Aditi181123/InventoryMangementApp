package com.stockpro.auth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;
import jakarta.mail.internet.MimeMessage;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;

import com.stockpro.auth.dto.ChangePasswordRequest;
import com.stockpro.auth.dto.CreateUserRequest;
import com.stockpro.auth.dto.JwtResponse;
import com.stockpro.auth.dto.LoginRequest;
import com.stockpro.auth.dto.UpdateProfileRequest;
import com.stockpro.auth.dto.UpdateUserRequest;
import com.stockpro.auth.dto.UserResponse;
import com.stockpro.auth.entity.Role;
import com.stockpro.auth.entity.User;
import com.stockpro.common.exception.BadRequestException;
import com.stockpro.common.exception.ResourceNotFoundException;
import com.stockpro.auth.repository.UserRepository;
import com.stockpro.auth.security.JwtUtil;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final JavaMailSender mailSender;
    private final RabbitTemplate rabbitTemplate;
    private final com.stockpro.common.client.AuditClient auditClient;

    @Value("${spring.mail.username}")
    private String mailUsername;

    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthenticationManager authenticationManager, JavaMailSender mailSender, RabbitTemplate rabbitTemplate, com.stockpro.common.client.AuditClient auditClient) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.mailSender = mailSender;
        this.rabbitTemplate = rabbitTemplate;
        this.auditClient = auditClient;
    }

    private void logAudit(String username, String action, String resource, String resourceId, String details) {
        try {
            java.util.Map<String, Object> log = new java.util.HashMap<>();
            log.put("username", username);
            log.put("action", action);
            log.put("resource", resource);
            log.put("resourceId", resourceId);
            log.put("details", details);
            auditClient.logAction(log);
        } catch (Exception e) {
            logger.warn("Failed to log audit action: {}", e.getMessage());
        }
    }

    @Override
    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        logger.info("Admin creating new user with email: {}", request.getEmail());

        // Only block if an active (non-deleted) user already has this email
        if (userRepository.findByEmail(request.getEmail()).map(u -> !Boolean.TRUE.equals(u.getIsDeleted())).orElse(false)) {
            throw new BadRequestException("Email already exists: " + request.getEmail());
        }

        String verificationToken = UUID.randomUUID().toString();
        Role role = request.getRole() != null ? request.getRole() : Role.STAFF;

        User user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .phone(request.getPhone())
                .role(role)
                .department(request.getDepartment())
                .isActive(true)
                .isEmailVerified(false)
                .verificationToken(verificationToken)
                .build();

        userRepository.save(user);
        logger.info("User created successfully with ID: {}. Sending verification email.", user.getUserId());

        sendVerificationEmail(user);

        return mapToUserResponse(user);
    }

    private void sendVerificationEmail(User user) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setFrom(mailUsername);
            helper.setTo(user.getEmail());
            helper.setSubject("Verify your StockPro Account");

            String frontendUrl = System.getenv("FRONTEND_URL") != null ? System.getenv("FRONTEND_URL") : "http://localhost:5173";
            String verificationLink = frontendUrl + "/verify-email?token=" + user.getVerificationToken();
            
            String content = String.format(
                "<h3>Welcome to StockPro, %s!</h3>" +
                "<p>An administrator has created an account for you.</p>" +
                "<p>Please click the link below to verify your email and activate your account:</p>" +
                "<p><a href='%s'>Verify Account</a></p>" +
                "<p>If the link doesn't work, copy and paste this URL into your browser:</p>" +
                "<p>%s</p>" +
                "<br><p>Best regards,<br>StockPro Team</p>",
                user.getFullName(), verificationLink, verificationLink
            );

            helper.setText(content, true);
            
            try {
                mailSender.send(message);
                logger.info("Verification email sent to: {}", user.getEmail());
            } catch (Exception mailEx) {
                logger.error("Failed to send real email (SMTP error): {}", mailEx.getMessage(), mailEx);
            }

            // Send to RabbitMQ for the local mock inbox service
            try {
                java.util.Map<String, Object> emailData = new java.util.HashMap<>();
                emailData.put("recipientEmail", user.getEmail());
                emailData.put("title", "Verify your StockPro Account");
                emailData.put("message", String.format("Welcome %s! Click the link below to verify your account:\n\n %s", user.getFullName(), verificationLink));
                emailData.put("severity", "INFO");
                emailData.put("type", "VERIFICATION");
                
                rabbitTemplate.convertAndSend("stockpro.alerts", emailData);
                logger.info("Verification notification sent to Mock Inbox (RabbitMQ) for: {}", user.getEmail());
            } catch (Exception amqpEx) {
                logger.error("Failed to send to RabbitMQ: {}", amqpEx.getMessage());
            }

        } catch (Exception e) {
            logger.error("Error in verification email process for: {}", user.getEmail(), e);
        }
    }

    @Override
    public JwtResponse login(LoginRequest request) {
        logger.info("User login attempt for email: {}", request.getEmail());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + request.getEmail()));

        if (Boolean.TRUE.equals(user.getIsDeleted())) {
            throw new BadRequestException("This account has been deleted");
        }

        if (!user.getIsActive()) {
            throw new BadRequestException("User account is deactivated");
        }

        if (!user.getIsEmailVerified()) {
            throw new BadRequestException("Email not verified. Please check your email inbox.");
        }

        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        String token = jwtUtil.generateToken(user.getEmail(), user.getUserId(), user.getRole().name());
        logger.info("User logged in successfully: {}", user.getEmail());

        logAudit(user.getEmail(), "USER_LOGIN", "AUTH", user.getUserId().toString(), "Login successful");

        return JwtResponse.builder()
                .token(token)
                .userId(user.getUserId())
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }

    @Override
    public UserResponse getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
        return mapToUserResponse(user);
    }

    @Override
    public UserResponse getProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public UserResponse updateProfile(String email, UpdateProfileRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (request.getFullName() != null) {
            user.setFullName(request.getFullName());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
         
        userRepository.save(user);
        logger.info("Profile updated for user: {}", email);

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public void changePassword(String email, ChangePasswordRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPasswordHash())) {
            throw new BadRequestException("Old password is incorrect");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        logger.info("Password changed for user: {}", email);
    }

    @Override
    @Transactional
    public UserResponse deactivateUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        user.setIsActive(false);
        userRepository.save(user);
        logger.info("User deactivated: {}", userId);

        logAudit("ADMIN", "DEACTIVATE_USER", "USER", userId.toString(), "User deactivated: " + user.getEmail());

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public UserResponse activateUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        user.setIsActive(true);
        userRepository.save(user);
        logger.info("User activated: {}", userId);

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public UserResponse updateUser(Long userId, UpdateUserRequest request) {
        logger.info("Admin updating user with ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        if (request.getFullName() != null) {
            user.setFullName(request.getFullName());
        }
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new BadRequestException("Email already exists: " + request.getEmail());
            }
            user.setEmail(request.getEmail());
        }
        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }
        if (request.getRole() != null) {
            user.setRole(request.getRole());
        }
        if (request.getDepartment() != null) {
            user.setDepartment(request.getDepartment());
        }

        userRepository.save(user);
        logger.info("User updated successfully with ID: {}", userId);

        logAudit("ADMIN", "UPDATE_USER", "USER", userId.toString(), "User details updated: " + user.getEmail());

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public void deleteUser(Long userId) {
        logger.warn("Soft deleting user with ID: {}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
        
        user.setIsDeleted(true);
        user.setIsActive(false);
        userRepository.save(user);
        logger.info("User marked as deleted: {}", userId);
    }

    @Override
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .filter(u -> !Boolean.TRUE.equals(u.getIsDeleted()))
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    @Override
    public void logout(String token) {
        logger.info("User logout requested"); 
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        logger.info("Email verification attempt with token: {}", token);
        User user = userRepository.findAll().stream()
                .filter(u -> token.equals(u.getVerificationToken()))
                .findFirst()
                .orElseThrow(() -> new BadRequestException("Invalid or expired verification token"));

        user.setIsEmailVerified(true);
        user.setVerificationToken(null);
        userRepository.save(user);
        logger.info("Email verified successfully for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public void resendVerificationEmail(String email) {
        logger.info("Request to resend verification email for: {}", email);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (user.getIsEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }

        if (Boolean.TRUE.equals(user.getIsDeleted())) {
            throw new BadRequestException("This account has been deleted");
        }

        String newVerificationToken = UUID.randomUUID().toString();
        user.setVerificationToken(newVerificationToken);
        userRepository.save(user);

        logger.info("Generated new verification token for user: {}. Resending email.", email);
        sendVerificationEmail(user);
    }

    @Override
    public boolean validateToken(String token) {
        try {
            return !jwtUtil.isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public JwtResponse refreshToken(String token) {
        String username = jwtUtil.extractUsername(token);
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + username));

        String newToken = jwtUtil.generateToken(user.getEmail(), user.getUserId(), user.getRole().name());
        return JwtResponse.builder()
                .token(newToken)
                .userId(user.getUserId())
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }

    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .userId(user.getUserId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .phone(user.getPhone())
                .role(user.getRole())
                .department(user.getDepartment())
                .isActive(user.getIsActive())
                .isEmailVerified(user.getIsEmailVerified())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }
}