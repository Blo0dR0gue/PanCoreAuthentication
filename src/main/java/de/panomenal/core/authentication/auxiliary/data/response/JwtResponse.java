package de.panomenal.core.authentication.auxiliary.data.response;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class JwtResponse {
    private String token;
    private String tokenType = "Bearer";
    private int id;
    private String username;
    private String email;
    private String role;
    private boolean twoFAAuthentication;

    public JwtResponse(String accessToken, int id, String username, String email, String role,
            boolean twoFAAuthentication) {
        this.token = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.twoFAAuthentication = twoFAAuthentication;
    }

    public JwtResponse(String accessToken) {
        this.token = accessToken;
    }

}