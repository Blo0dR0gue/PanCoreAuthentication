package de.panomenal.core.authentication.auxiliary.data.response;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
@AllArgsConstructor
public class VerifyResponse {

    private String status;
    private boolean isAuthenticated;
    private String username;
    private List<GrantedAuthority> authorities;

}
