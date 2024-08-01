package org.sid.userManagement_service.dtos;

import lombok.Data;
import org.sid.userManagement_service.models.ApiModel;

import java.util.ArrayList;
import java.util.List;

@Data
public class UserDto {
    private String keycloakId;
    private String email;
    private String name;
    private String username;
    private String password;
    private List<String> roles = new ArrayList<>();
    private List<String> apiModelsIds = new ArrayList<>();
    private List<ApiModel> apiModels = new ArrayList<>();
}
