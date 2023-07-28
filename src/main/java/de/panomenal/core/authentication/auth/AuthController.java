package de.panomenal.core.authentication.auth;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import de.panomenal.core.AppConstants;
import de.panomenal.core.authentication.auxiliary.exceptions.types.AuthenticationException;

@Controller
@RequestMapping(path = AppConstants.AUTH_URL)
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    // TODO: login, register, verify, refresh

    private void authenticate(String username, String password) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new AuthenticationException("User is disabled", e);
        } catch (BadCredentialsException e) {
            throw new AuthenticationException("Credentials are invalid", e);
        }
    }

}
