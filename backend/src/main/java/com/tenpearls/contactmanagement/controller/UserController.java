package com.tenpearls.contactmanagement.controller;

import com.tenpearls.contactmanagement.model.User;
import com.tenpearls.contactmanagement.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
            // Validate required fields
            if (user.getName() == null || user.getName().trim().isEmpty() ||
                    user.getEmail() == null || user.getEmail().trim().isEmpty() ||
                    user.getPassword() == null || user.getPassword().trim().isEmpty()) {
                response.put("status", "error");
                response.put("message", "Name, email, and password are required");
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
            savedUser.setPassword(null);

            response.put("status", "success");
            response.put("message", "User registered successfully");
            response.put("user", savedUser);
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Registration failed: " + e.getMessage());
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
                response.put("message", "Email and password are required");
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }

            // Find user by email
            Optional<User> emailInDb = userService.getByEmail(userEmail);
            if (emailInDb.isEmpty()) {
                response.put("status", "error");
                response.put("message", "User not found with this email");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Verify password
            User loggedInUser = emailInDb.get();
            if (!loggedInUser.getPassword().equals(userPassword)) {
                response.put("status", "error");
                response.put("message", "Incorrect password");
                return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
            }

            // Return user details without password
            loggedInUser.setPassword(null);
            response.put("status", "success");
            response.put("message", "Login successful");
            response.put("user", loggedInUser);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Login failed: " + e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PutMapping("/update-pwd")
    public ResponseEntity<Map<String, Object>> updateUser(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        try {
            // Find user by email
            Optional<User> userInDb = userService.getByEmail(user.getEmail());

            if (userInDb.isEmpty()) {
                response.put("status", "error");
                response.put("message", "User not found with this email");
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }

            // Get existing user from database
            User existingUser = userInDb.get();

            // Update password (encode here if using BCrypt)
            existingUser.setPassword(user.getPassword());

            // Save updated user to database
            userService.createUser(existingUser);

            response.put("status", "success");
            response.put("message", "Password updated successfully");
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Failed to update password: " + e.getMessage());
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


}
