package com.stockpro.auth.config;

import com.stockpro.auth.entity.Role;
import com.stockpro.auth.entity.User;
import com.stockpro.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!userRepository.existsByEmail("tanuaditi04@gmail.com")) {
            User admin = User.builder()
                    .fullName("System Administrator")
                    .email("tanuaditi04@gmail.com")
                    .passwordHash(passwordEncoder.encode("Aditi@123"))
                    .role(Role.ADMIN)
                    .isActive(true)
                    .isEmailVerified(true)
                    .build();
            userRepository.save(admin);
            logger.info("Default ADMIN user created: tanuaditi04@gmail.com / Aditi@123");
        } else {
            userRepository.findByEmail("tanuaditi04@gmail.com").ifPresent(user -> {
                boolean updated = false;
                if (!user.getIsEmailVerified()) {
                    user.setIsEmailVerified(true);
                    updated = true;
                }
                if (user.getRole() != Role.ADMIN) {
                    user.setRole(Role.ADMIN);
                    updated = true;
                }
                if (updated) {
                    userRepository.save(user);
                    logger.info("Updated existing admin user permissions: tanuaditi04@gmail.com");
                }
            });
            logger.info("Default ADMIN user already exists, verification checked.");
        }
    }
}
