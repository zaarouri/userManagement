package org.sid.userManagement_service.mappers;

import org.mapstruct.Mapper;
import org.sid.userManagement_service.dtos.UserDto;
import org.sid.userManagement_service.entities.UserModel;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserModel toEntity(UserDto userDto);
    UserDto toDto(UserModel userModel);

}
