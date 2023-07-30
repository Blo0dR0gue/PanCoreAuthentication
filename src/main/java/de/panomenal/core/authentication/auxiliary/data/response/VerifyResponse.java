package de.panomenal.core.authentication.auxiliary.data.response;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class VerifyResponse {

    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;

    public VerifyResponse(UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) {
        this.usernamePasswordAuthenticationToken = usernamePasswordAuthenticationToken;
    }

}
