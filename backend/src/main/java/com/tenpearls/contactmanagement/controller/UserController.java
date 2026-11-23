package com.tenpearls.contactmanagement.controller;

import com.tenpearls.contactmanagement.model.User;
import com.tenpearls.contactmanagement.services.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    // Constructor injection
    public UserController(UserService userService) {
        this.userService = userService;
    }

    // Register a new user
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> createNewUser(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        try {
            user.setId(null);

            // Validate required fields
            if (user.getName() == null || user.getName().trim().isEmpty() ||
                    user.getEmail() == null || user.getEmail().trim().isEmpty() ||
                    user.getPassword() == null || user.getPassword().trim().isEmpty()) {
                response.put("status", "error");
                response.put("message", "Name, email, and password are required");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            // Trim name and email so length checks match persisted values
            user.setName(user.getName().trim());
            user.setEmail(user.getEmail().trim());

            if (user.getName().length() > 50) {
                response.put("status", "error");
                response.put("message", "Name must not exceed 50 characters");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            if (user.getEmail().length() > 100) {
                response.put("status", "error");
                response.put("message", "Email must not exceed 100 characters");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            if (passwordExceedsMaxLength(user.getPassword())) {
                response.put("status", "error");
                response.put("message", "Password must not exceed 72 UTF-8 bytes");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            // Check if email already exists
            if (userService.getByEmail(user.getEmail()).isPresent()) {
                response.put("status", "error");
                response.put("message", "Email is already registered");
                return new ResponseEntity<>(response, HttpStatus.CONFLICT);
            }

            // Save user and hide password in response
            User savedUser = userService.createUser(user);
            User responseUser = safeUserResponse(savedUser);

            response.put("status", "success");
            response.put("message", "User registered successfully");
            response.put("user", responseUser);
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (DataIntegrityViolationException e) {
            response.put("status", "error");
            response.put("message", "Email is already registered");
            return new ResponseEntity<>(response, HttpStatus.CONFLICT);
        } catch (Exception e) {
            log.error("Registration failed", e);
            response.put("status", "error");
            response.put("message", "Registration failed");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Authenticate existing user
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        try {
            String userEmail = user.getEmail();
            String userPassword = user.getPassword();

            // Validate email and password
            if (userEmail == null || userEmail.trim().isEmpty() ||
                    userPassword == null || userPassword.trim().isEmpty()) {
                response.put("status", "error");
                response.put("message", "Invalid email or password");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Find user by email
            Optional<User> emailInDb = userService.getByEmail(userEmail);
            if (emailInDb.isEmpty()) {
                response.put("status", "error");
                response.put("message", "Invalid email or password");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Verify password
            User loggedInUser = emailInDb.get();
            if (!userService.verifyPassword(userPassword, loggedInUser.getPassword())) {
                response.put("status", "error");
                response.put("message", "Invalid email or password");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Return user details without password
            User responseUser = safeUserResponse(loggedInUser);
            response.put("status", "success");
            response.put("message", "Login successful");
            response.put("user", responseUser);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Login failed");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PutMapping("/update-pwd")
    public ResponseEntity<Map<String, Object>> updateUser(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        try {
            String replacementPassword = user.getPassword();
            if (replacementPassword == null || replacementPassword.trim().isEmpty()) {
                response.put("status", "error");
                response.put("message", "Replacement password is required");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            if (passwordExceedsMaxLength(replacementPassword)) {
                response.put("status", "error");
                response.put("message", "Password must not exceed 72 UTF-8 bytes");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            // Find user by email
            Optional<User> userInDb = userService.getByEmail(user.getEmail());

            if (userInDb.isEmpty()) {
                response.put("status", "error");
                response.put("message", "Password update denied");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Get existing user from database
            User existingUser = userInDb.get();

            // Require proof of control of the target account before changing anything.
            if (user.getCurrentPassword() == null
                    || !userService.verifyPassword(user.getCurrentPassword(), existingUser.getPassword())) {
                response.put("status", "error");
                response.put("message", "Password update denied");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            userService.updatePassword(existingUser, replacementPassword);

            response.put("status", "success");
            response.put("message", "Password updated successfully");
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Password update failed");
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private User safeUserResponse(User user) {
        return User.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .createdAt(user.getCreatedAt())
                .password(null)
                .build();
    }

    private boolean passwordExceedsMaxLength(String password) {
        return password.getBytes(StandardCharsets.UTF_8).length > 72;
    }
}
