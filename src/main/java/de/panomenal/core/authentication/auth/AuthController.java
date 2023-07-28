package de.panomenal.core.authentication.auth;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import de.panomenal.core.AppConstants;
import de.panomenal.core.authentication.auth.jwt.JwtUtils;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsImpl;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsServiceImpl;
import de.panomenal.core.authentication.auxiliary.data.request.LoginRequest;
import de.panomenal.core.authentication.auxiliary.data.request.RegisterRequest;
import de.panomenal.core.authentication.auxiliary.data.response.JwtResponse;
import de.panomenal.core.authentication.auxiliary.data.response.SignUpResponse;
import de.panomenal.core.authentication.auxiliary.exceptions.types.AuthenticationException;
import de.panomenal.core.authentication.auxiliary.exceptions.types.Invalid2FACodeException;
import de.panomenal.core.authentication.user.UserService;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

@Controller
@RequestMapping(path = AppConstants.AUTH_URL)
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserService userService;

    @Autowired
    QrDataFactory qrDataFactory;

    @Autowired
    QrGenerator qrGenerator;

    @Autowired
    CodeVerifier verifier;

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
    public ResponseEntity<SignUpResponse> registerRequest(@Valid @RequestBody RegisterRequest registerRequest) {
        if (registerRequest.isUsing2FA() && registerRequest.getTwoFACode() == null) {
            // Is using 2FA but does not provided a code yet. (First register)
            userService.checkIfUserExists(registerRequest.getUsername(), registerRequest.getEmail());

            String secret = userService.generate2FASecret();
            QrData qrData = qrDataFactory.newBuilder().label(registerRequest.getEmail()).secret(secret)
                    .issuer(AppConstants.QR_ISSUER).build();

            try {
                String qrCodeImg = getDataUriForImage(qrGenerator.generate(qrData), qrGenerator.getImageMimeType());
                return ResponseEntity.ok().body(new SignUpResponse(true, qrCodeImg, secret, false));
            } catch (QrGenerationException e) {
                e.printStackTrace();
            }
        } else if (registerRequest.isUsing2FA() && registerRequest.getTwoFACode() != null) {
            // Is using 2FA code validation.
            if (!verifier.isValidCode(registerRequest.getTwoFASecret(), registerRequest.getTwoFACode())) {
                return ResponseEntity.ok(new SignUpResponse(true, null, null, false));
            } else {
                userService.registerUser(registerRequest);
                return ResponseEntity.ok(new SignUpResponse(true, null, null, true));
            }
        } else {
            // Is not using 2FA
            userService.registerUser(registerRequest);
            return ResponseEntity.ok(new SignUpResponse(false, null, null, true));
        }
        return ResponseEntity.badRequest().body(new SignUpResponse(false, null, null, false));
    }

    @GetMapping(AppConstants.VERIFY_PATH)
    public ResponseEntity<?> verifyRequest() {
        return null;
    }

    @GetMapping(AppConstants.VERIFY_TWO_FA_PATH)
    @PreAuthorize("hasRole('ROLE_PRE_VERIFICATION_USER')")
    public ResponseEntity<JwtResponse> verifyTwoFARequest(@NotEmpty @RequestBody String twoFACode,
            @AuthenticationPrincipal UserDetailsImpl userDetails) throws Invalid2FACodeException {
        if (!verifier.isValidCode(userDetails.getSecret(), twoFACode)) {
            throw new Invalid2FACodeException("Invalid Code");
        }
        String jwt = jwtUtils.generateToken(userDetails, true);

        String role = userDetails.getAuthority().getAuthority();

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                role,
                true));
    }

    @GetMapping(AppConstants.REFRESH_PATH)
    public ResponseEntity<JwtResponse> refreshRequest(@NotEmpty HttpServletRequest request) {
        String authToken = request.getHeader(AppConstants.AUTH_HEADER);
        // remove bearer + space
        final String token = authToken.substring(7);
        String username = jwtUtils.getUsernameFromToken(token);
        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(username);

        if (jwtUtils.canTokenBeRefreshed(token) && userDetails.canLogin()) {
            String refreshedToken = jwtUtils.refreshToken(token);
            // Just send back the token
            return ResponseEntity.ok(new JwtResponse(refreshedToken));
        } else {
            // Token cant be refreshed because it is expired or user cant login anymore
            return ResponseEntity.badRequest().body(new JwtResponse(null));
        }
    }

    @GetMapping(AppConstants.LOGOUT_PATH)
    public ResponseEntity<?> logoutRequest() {
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
        } catch (org.springframework.security.core.AuthenticationException e) {
            throw new AuthenticationException("Authentication failed", e);
        }
    }

}
