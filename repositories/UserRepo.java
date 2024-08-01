package org.sid.userManagement_service.repositories;

import org.sid.userManagement_service.entities.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepo extends JpaRepository<UserModel, String> {
    Optional<UserModel> findByUsername(String username);
    Optional<UserModel> findByKeycloakId(String keycloakId);
    void deleteByKeycloakId(String keycloakId);

    }

