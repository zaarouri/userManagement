package org.sid.userManagement_service.services;

import org.sid.userManagement_service.dtos.AuthResponse;

public interface AuthenticationService {

    AuthResponse login(String username, String password);
    String hashPassword(String password);
    void logout(String token);
}
