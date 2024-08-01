package org.sid.userManagement_service.services;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;
import org.sid.userManagement_service.dtos.AuthResponse;
import org.sid.userManagement_service.dtos.UserDto;
import org.sid.userManagement_service.entities.UserModel;

import org.sid.userManagement_service.exception.AuthenticationException;
import org.sid.userManagement_service.exception.InvalidCredentialsException;

import org.sid.userManagement_service.exception.KeycloakUnavailableException;
import org.sid.userManagement_service.exception.UserNotFoundException;

import org.sid.userManagement_service.mappers.UserMapper;
import org.sid.userManagement_service.repositories.UserRepo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.ws.rs.NotAuthorizedException;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepo userRepository;
    private final Keycloak keycloak;
    private final UserMapper mapper;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.keycloak.realm}")
    private String realm;
    @Value("${app.keycloak.admin.clientId}")
    private String clientId;
    @Value("${app.keycloak.admin.clientSecret}")
    private String clientSecret;
    @Value("${app.keycloak.serverUrl}")
    private String serverUrl;

    @Override
    public AuthResponse login(String username, String password) {
        try {
            return loginWithKeycloak(username, password);
        } catch (KeycloakUnavailableException e) {
            log.warn("Keycloak login unavailable. Falling back to local login.", e);
            return loginLocal(username, password);
        }
    }

    private AuthResponse loginWithKeycloak(String username, String password) {
        try {
            Keycloak keycloakClient = Keycloak.getInstance(
                    serverUrl,
                    realm,
                    username,
                    password,
                    clientId,
                    clientSecret
            );

            AccessTokenResponse tokenResponse = keycloakClient.tokenManager().getAccessToken();
            if (tokenResponse == null || tokenResponse.getToken() == null) {
                throw new AuthenticationException("Failed to obtain access token from Keycloak");
            }

            UserModel user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UserNotFoundException("User not found in local database"));
            UserDto userDto = mapper.toDto(user);

            return new AuthResponse(tokenResponse.getToken(), userDto);

        } catch (NotAuthorizedException e) {
            throw new InvalidCredentialsException("Invalid credentials", e);
        } catch (Exception e) {
            throw new KeycloakUnavailableException("Keycloak server is unavailable", e);
        }
    }

    private AuthResponse loginLocal(String username, String password) {
        UserModel user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (verifyPassword(password, user.getPassword())) {
            UserDto userDto = mapper.toDto(user);
            return new AuthResponse("local_login_successful", userDto);
        } else {
            throw new InvalidCredentialsException("Invalid credentials");
        }
    }

    private boolean verifyPassword(String inputPassword, String storedHash) {
        return passwordEncoder.matches(inputPassword, storedHash);
    }
    @Override
    public String hashPassword(String password) {
        return passwordEncoder.encode(password);
    }
    @Override
    public void logout(String token) {
        try {
            keycloak.tokenManager().invalidate(token);
        } catch (Exception e) {
            log.error("Error during logout", e);
            throw new AuthenticationException("Failed to logout", e);
        }
    }
}