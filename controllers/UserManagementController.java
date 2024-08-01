package org.sid.userManagement_service.controllers;

import lombok.RequiredArgsConstructor;
import org.sid.userManagement_service.dtos.UserDto;
import org.sid.userManagement_service.dtos.UserProfileDto;
import org.sid.userManagement_service.services.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin")
public class UserManagementController {
    private final UserService userService;
    @GetMapping("/users-all")
    public List<UserDto> getAllUsers() {
        return userService.getAllUsers();
    }

    @GetMapping("/users/{keycloakId}")
    public UserDto getUserById(@PathVariable String keycloakId) {
        return userService.getUserById(keycloakId);
    }
    @PostMapping("/users-save")
    public UserDto createUser(@RequestBody UserDto userDto) {
        return userService.createUser(userDto);
    }
   @PutMapping("/users-update/{keycloakId}")
    public UserDto updateUser(@PathVariable String keycloakId,@RequestBody UserDto userDto) {
        return userService.updateUser(keycloakId,userDto);
    }
    @DeleteMapping("/users-delete/{keycloakId}")
    public UserDto deleteUser(@PathVariable String keycloakId) {
            return userService.deleteUser(keycloakId);
    }

    @GetMapping("/users-profile/{keycloakId}")
    public UserProfileDto getProfile(@PathVariable String keycloakId) {
        return userService.getProfile(keycloakId);
    }
    @PostMapping("/users-assignUserToApi")
    public UserDto assignUserToApi(@RequestParam String apiId, @RequestParam String keycloakId) {
        UserDto userDto = userService.assignApiModeltoUser(apiId, keycloakId);
        return userDto;
    }
}
