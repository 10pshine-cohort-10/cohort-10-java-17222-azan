package com.tenpearls.contactmanagement;

import com.tenpearls.contactmanagement.controller.UserController;
import com.tenpearls.contactmanagement.model.User;
import com.tenpearls.contactmanagement.services.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class UserControllerPasswordTests {

    private final UserService userService = mock(UserService.class);
    private final UserController controller = new UserController(userService);

    @Test
    void createRejectsPasswordOver72Utf8Bytes() {
        User user = User.builder()
                .name("Test")
                .email("test@example.com")
                .password("é".repeat(37))
                .build();

        assertEquals(HttpStatus.BAD_REQUEST,
                controller.createNewUser(user).getStatusCode());
    }

    @Test
    void updateRejectsPasswordOver72Utf8Bytes() {
        User user = User.builder()
                .email("test@example.com")
                .password("a".repeat(73))
                .build();

        assertEquals(HttpStatus.BAD_REQUEST,
                controller.updateUser(user).getStatusCode());
    }
}
