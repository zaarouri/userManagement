package org.sid.userManagement_service.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.sid.userManagement_service.models.ApiModel;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;


@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserModel {
    @Id
    private String keycloakId;
    private String email;
    private String username;
    private String name;
    private String password;
    @ElementCollection
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "keycloak_id"))
    @Column(name = "role")
    private List<String> roles = new ArrayList<>();
    @ElementCollection
    @CollectionTable(name = "user_api", joinColumns = @JoinColumn(name = "user_keycloakId"))
    @Column(name = "api_id")
    private List<String> apiModelsIds = new ArrayList<>();
    @Transient
    private List<ApiModel> apiModels = new ArrayList<>();

}