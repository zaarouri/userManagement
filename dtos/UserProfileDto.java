package org.sid.userManagement_service.dtos;

import lombok.Data;

import java.util.List;

@Data
public class UserProfileDto {
    private String email;
    private String username;
    private String name;
    private List<String> roles;
}
