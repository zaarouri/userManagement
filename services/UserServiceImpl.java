package org.sid.userManagement_service.services;

import jakarta.transaction.Transactional;
import jakarta.ws.rs.ForbiddenException;
import lombok.RequiredArgsConstructor;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.sid.userManagement_service.exception.InvalidEmailException;
import org.sid.userManagement_service.exception.InvalidPasswordException;
import org.sid.userManagement_service.exception.KeycloakUpdateException;
import org.sid.userManagement_service.exception.UserNotFoundException;

import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.sid.userManagement_service.clients.ApiModelRestClient;
import org.sid.userManagement_service.dtos.UserDto;
import org.sid.userManagement_service.dtos.UserProfileDto;
import org.sid.userManagement_service.entities.UserModel;
import org.sid.userManagement_service.mappers.UserMapper;
import org.sid.userManagement_service.models.ApiModel;
import org.sid.userManagement_service.repositories.UserRepo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional
public class UserServiceImpl implements UserService {

    private static final int MIN_PASSWORD_LENGTH = 6;
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{" + MIN_PASSWORD_LENGTH + ",}$"
    );
    private final ApiModelRestClient apiModelRestClient;
    private final UserMapper mapper;
    private final AuthenticationService authenticationService;
    private final UserRepo userRepository;
    private final Keycloak keycloak;
    @Value("${app.keycloak.realm}")
    private String realm;
    @Value("${app.keycloak.admin.clientId}")
    private String clientId;
    @Value("${app.keycloak.admin.clientSecret}")
    private String clientSecret;

    @Value("${app.keycloak.serverUrl}")
    private String serverUrl;

    @Override
    public List<UserDto> getAllUsers() {
        List<UserModel> userModels = userRepository.findAll();
        return userModels.stream().map(mapper::toDto).collect(Collectors.toList());
    }

    @Override
    public UserDto getUserById(String keycloakId) {
        UserModel userModel = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + keycloakId));
        return mapper.toDto(userModel);
    }

    @Override
    public UserDto createUser(UserDto userDto) {
        validatePassword(userDto.getPassword());
        validateEmail(userDto.getEmail());
        String keycloakId = createUserInKeycloak(userDto);
        if (keycloakId == null || keycloakId.isEmpty()) {
            throw new KeycloakUpdateException("Failed to generate Keycloak ID", null);
        }
        UserModel userModel = mapper.toEntity(userDto);
        userModel.setKeycloakId(keycloakId);
        userModel.setPassword(authenticationService.hashPassword(userDto.getPassword()));
        userModel.setRoles(userDto.getRoles());
        UserModel saved = userRepository.save(userModel);
        return mapper.toDto(saved);
    }

    public UserDto updateUser(String keycloakId, UserDto userDto) {
        UserModel userModel = userRepository.findById(keycloakId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + keycloakId));

        if (userDto.getEmail() != null && !userDto.getEmail().equals(userModel.getEmail())) {
            validateEmail(userDto.getEmail());
        }

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            validatePassword(userDto.getPassword());
            userModel.setPassword(authenticationService.hashPassword(userDto.getPassword()));
        }
        try {
            updateUserInKeycloak(keycloakId, userDto);
        } catch (Exception e) {
            log.error("Error updating user in Keycloak", e);
            throw new KeycloakUpdateException("Failed to update user in Keycloak", e);
        }

        userModel.setName(userDto.getName());
        userModel.setEmail(userDto.getEmail());
        userModel.setUsername(userDto.getUsername());
        userModel.setRoles(userDto.getRoles());

        UserModel updatedUser = userRepository.save(userModel);
        log.info("User updated successfully: {}", updatedUser.getKeycloakId());

        return mapper.toDto(updatedUser);
    }


    @Override
    public UserDto deleteUser(String keycloakId) {
        log.info("Attempting to delete user with keycloakId: {}", keycloakId);
        UserModel userModel = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + keycloakId));
        UsersResource usersResource = getUsersResource();
        usersResource.delete(keycloakId);
        userRepository.deleteByKeycloakId(keycloakId);
        return mapper.toDto(userModel);
    }

    @Override
    public UserProfileDto getProfile(String keycloakId) {
        UserModel userModel = userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + keycloakId));

        UserProfileDto userProfile = new UserProfileDto();
        userProfile.setEmail(userModel.getEmail());
        userProfile.setUsername(userModel.getUsername());
        userProfile.setName(userModel.getName());
        userProfile.setRoles(userModel.getRoles());

        return userProfile;
    }
    @Override
    public UserDto assignApiModeltoUser(String apiId, String keycloakId) {
        ApiModel apiModel = apiModelRestClient.getById(apiId);
        if (apiModel == null) {
            throw new RuntimeException("ApiModel not found");
        }

        UserModel userModel = userRepository.findById(keycloakId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + keycloakId));

        List<String> apiModelsIds = Optional.ofNullable(userModel.getApiModelsIds()).orElse(new ArrayList<>());
        if (!apiModelsIds.contains(apiId)) {
            apiModelsIds.add(apiId);
        }
        userModel.setApiModelsIds(apiModelsIds);

        userRepository.save(userModel);

        UserDto userDto = mapper.toDto(userModel);
        List<ApiModel> apiModels = apiModelsIds.stream()
                .map(apiModelRestClient::getById)
                .collect(Collectors.toList());
        userDto.setApiModels(apiModels);

        return userDto;
    }
    private String createUserInKeycloak(UserDto userDto) {
        validateEmail(userDto.getEmail());
        validatePassword(userDto.getPassword());

        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setEnabled(true);
        userRepresentation.setUsername(userDto.getUsername());
        userRepresentation.setEmail(userDto.getEmail());
        userRepresentation.setEmailVerified(false);

        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setValue(userDto.getPassword());
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setTemporary(false);

        userRepresentation.setCredentials(List.of(credentialRepresentation));

        UsersResource usersResource = getUsersResource();
        Response response = usersResource.create(userRepresentation);

        log.info("Status Code: " + response.getStatus());

        if (response.getStatus() != 201) {
            String errorMessage = response.readEntity(String.class);
            log.error("Error creating user in Keycloak: " + errorMessage);
            throw new KeycloakUpdateException("Failed to create user in Keycloak. Status code: " + response.getStatus(), null);
        }

        String keycloakUserId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        log.info("New user has been created in Keycloak with ID: " + keycloakUserId);

        if (userDto.getRoles() != null && !userDto.getRoles().isEmpty()) {
            assignRolesToUserInKeycloak(keycloakUserId, userDto.getRoles());
        } else {
            log.warn("No roles provided for user: " + userDto.getUsername());
        }

        return keycloakUserId;
    }

    private void updateUserInKeycloak(String keycloakId, UserDto userDto) {
        UsersResource usersResource = getUsersResource();
        UserRepresentation userRepresentation = usersResource.get(keycloakId).toRepresentation();

        if (userDto.getEmail() != null && !userDto.getEmail().equals(userRepresentation.getEmail())) {
            validateEmail(userDto.getEmail());
        }

        userRepresentation.setUsername(userDto.getUsername());
        userRepresentation.setEmail(userDto.getEmail());
        userRepresentation.setFirstName(userDto.getName());

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            validatePassword(userDto.getPassword());
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(userDto.getPassword());
            credential.setTemporary(false);
            usersResource.get(keycloakId).resetPassword(credential);
            log.info("Password updated for user: {}", keycloakId);
        }

        if (userDto.getRoles() != null) {
            updateRolesForUserInKeycloak(keycloakId, userDto.getRoles());
        } else {
            log.warn("No roles provided for user update: {}", userDto.getUsername());
        }

        try {
            usersResource.get(keycloakId).update(userRepresentation);
            log.info("User updated in Keycloak: {}", keycloakId);
        } catch (Exception e) {
            throw new KeycloakUpdateException("Failed to update user in Keycloak", e);
        }
    }

    private void assignRolesToUserInKeycloak(String keycloakUserId, List<String> roleNames) {
        try {
            UsersResource usersResource = getUsersResource();
            List<RoleRepresentation> roleRepresentations = new ArrayList<>();

            for (String roleName : roleNames) {
                RoleRepresentation roleRepresentation = getRoleRepresentation().get(roleName).toRepresentation();
                if (roleRepresentation == null) {
                    log.warn("Role " + roleName + " not found in Keycloak");
                    continue;
                }
                roleRepresentations.add(roleRepresentation);
            }

            if (roleRepresentations.isEmpty()) {
                throw new KeycloakUpdateException("No valid roles found to assign.", null);
            }

            usersResource.get(keycloakUserId).roles().realmLevel().add(roleRepresentations);
            log.info("Assigned roles " + roleNames + " to user " + keycloakUserId);
        } catch (ForbiddenException e) {
            throw new KeycloakUpdateException("Insufficient permissions to assign roles to user " + keycloakUserId, e);
        } catch (Exception e) {
            throw new KeycloakUpdateException("Failed to assign roles to user " + keycloakUserId, e);
        }
    }

    private void updateRolesForUserInKeycloak(String keycloakUserId, List<String> newRoles) {
        try {
            UserResource userResource = getUsersResource().get(keycloakUserId);

            List<RoleRepresentation> currentRoles = userResource.roles().realmLevel().listAll();
            List<RoleRepresentation> allRealmRoles = getRoleRepresentation().list();

            List<RoleRepresentation> rolesToAdd = new ArrayList<>();
            List<RoleRepresentation> rolesToRemove = new ArrayList<>();

            for (RoleRepresentation role : allRealmRoles) {
                if (newRoles.contains(role.getName()) && !currentRoles.contains(role)) {
                    rolesToAdd.add(role);
                } else if (!newRoles.contains(role.getName()) && currentRoles.contains(role)) {
                    rolesToRemove.add(role);
                }
            }

            if (!rolesToRemove.isEmpty()) {
                userResource.roles().realmLevel().remove(rolesToRemove);
            }

            if (!rolesToAdd.isEmpty()) {
                userResource.roles().realmLevel().add(rolesToAdd);
            }

            log.info("Roles updated for user " + keycloakUserId);
        } catch (Exception e) {
            throw new KeycloakUpdateException("Failed to update roles for user " + keycloakUserId, e);
        }
    }
    private void validatePassword(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new InvalidPasswordException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new InvalidPasswordException("Password must contain at least one digit, one lowercase letter, " +
                    "one uppercase letter, one special character, and no whitespace");
        }
    }

    private void validateEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
        Pattern pattern = Pattern.compile(emailRegex);
        if (!pattern.matcher(email).matches()) {
            throw new InvalidEmailException("Invalid email format: " + email);
        }
    }
    private UsersResource getUsersResource(){
        return keycloak.realm(realm).users();
    }
    private RolesResource getRoleRepresentation(){
        return keycloak.realm(realm).roles();
    }
}
