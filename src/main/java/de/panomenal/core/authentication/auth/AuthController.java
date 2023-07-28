package de.panomenal.core.authentication.auth;

import java.util.Objects;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import de.panomenal.core.AppConstants;
import de.panomenal.core.authentication.auth.jwt.JwtUtils;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsImpl;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsServiceImpl;
import de.panomenal.core.authentication.auxiliary.data.request.LoginRequest;
import de.panomenal.core.authentication.auxiliary.data.response.JwtResponse;
import de.panomenal.core.authentication.auxiliary.exceptions.types.AuthenticationException;
import jakarta.validation.Valid;

@Controller
@RequestMapping(path = AppConstants.AUTH_URL)
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    JwtUtils jwtUtils;

    @GetMapping(AppConstants.LOGIN_PATH)
    public ResponseEntity<JwtResponse> loginRequest(@Valid @RequestBody LoginRequest loginRequest) {
        authenticate(loginRequest.getUsername(), loginRequest.getPassword());

        // TODO: handle logout (add token to blacklist if still valid)
        // TODO: Account Lockout for brute force protection

        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
        boolean twoFAAuthentication = userDetails.isUsing2FA();

        String jwtToken = jwtUtils.generateToken(userDetails, twoFAAuthentication);

        String role = userDetails.getAuthority().getAuthority();

        return ResponseEntity.ok(new JwtResponse(jwtToken, userDetails.getId(), userDetails.getUsername(),
                userDetails.getEmail(), role, twoFAAuthentication));
    }

    @GetMapping(AppConstants.REGISTER_PATH)
    public ResponseEntity<?> registerRequest() {
        return null;
    }

    @GetMapping(AppConstants.VERIFY_PATH)
    public ResponseEntity<?> verifyRequest() {
        return null;
    }

    @GetMapping(AppConstants.VERIFY_TWO_FA_PATH)
    @PreAuthorize("hasRole('ROLE_PRE_VERIFICATION_USER')")
    public ResponseEntity<?> verifyTwoFARequest() {
        return null;
    }

    @GetMapping(AppConstants.REFRESH_PATH)
    public ResponseEntity<?> refreshRequest() {
        return null;
    }

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
