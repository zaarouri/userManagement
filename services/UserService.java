package org.sid.userManagement_service.services;

import org.sid.userManagement_service.dtos.UserDto;
import org.sid.userManagement_service.dtos.UserProfileDto;

import java.util.List;

public interface UserService {
    List<UserDto> getAllUsers();
    UserDto getUserById(String keycloakId);
    UserDto createUser(UserDto userDto);
    UserDto updateUser(String keycloakId,UserDto userDto);
    UserDto deleteUser(String keycloakId);
    UserProfileDto getProfile(String keycloakId);
    UserDto assignApiModeltoUser(String apiId, String keycloakId);

}
