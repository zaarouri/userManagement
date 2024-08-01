package org.sid.userManagement_service.controllers;

import lombok.RequiredArgsConstructor;
import org.sid.userManagement_service.dtos.AuthResponse;
import org.sid.userManagement_service.dtos.LoginRequest;
import org.sid.userManagement_service.dtos.UserDto;
import org.sid.userManagement_service.services.AuthenticationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")

public class AuthController {
    private final AuthenticationService authService;

    @PostMapping("/login")
    public UserDto login(@RequestBody LoginRequest loginRequest) {
        AuthResponse authResponse = authService.login(loginRequest.getUsername(), loginRequest.getPassword());
        return authResponse.getUser();
    }

    @PostMapping("/logout")
    public String logout(@RequestHeader("Authorization") String token) {
        authService.logout(token);
        return "Logged out successfully";
    }
}
