package org.sid.userManagement_service.models;
import lombok.Data;

import java.util.Date;
import java.util.HashMap;

import java.util.Map;
@Data
public class ApiModel {
    private String id;
    private String name ;
    private String url;
    private String type; // SOAP or REST
    private String username ;
    private String password ;
    private Date createdAt ;
    private Map<String, String> headers = new HashMap<>();
}
