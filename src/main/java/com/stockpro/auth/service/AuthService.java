package com.stockpro.auth.service;

import com.stockpro.auth.dto.*;

import java.util.List;

public interface AuthService {

    UserResponse createUser(CreateUserRequest request);

    JwtResponse login(LoginRequest request);

    UserResponse getUserById(Long userId);

    UserResponse getProfile(String email);

    UserResponse updateProfile(String email, UpdateProfileRequest request);

    void changePassword(String email, ChangePasswordRequest request);

    UserResponse deactivateUser(Long userId);

    UserResponse activateUser(Long userId);

    UserResponse updateUser(Long userId, UpdateUserRequest request);

    void deleteUser(Long userId);

    List<UserResponse> getAllUsers();

    void logout(String token);

    void verifyEmail(String token);

    void resendVerificationEmail(String email);

    boolean validateToken(String token);

    JwtResponse refreshToken(String token);
}