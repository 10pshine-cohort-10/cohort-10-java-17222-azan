package com.tenpearls.contactmanagement.services;

import com.tenpearls.contactmanagement.model.User;
import com.tenpearls.contactmanagement.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User createUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public Optional<User> getByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public boolean verifyPassword(String rawPassword, String storedPasswordHash) {
        return storedPasswordHash != null
                && passwordEncoder.matches(rawPassword, storedPasswordHash);
    }

    public User updatePassword(User existingUser, String replacementPassword) {
        existingUser.setPassword(passwordEncoder.encode(replacementPassword));
        return userRepository.save(existingUser);
    }
}
