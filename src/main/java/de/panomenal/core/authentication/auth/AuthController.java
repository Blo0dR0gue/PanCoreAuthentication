package de.panomenal.core.authentication.auth;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import de.panomenal.core.authentication.AppConstants;
import de.panomenal.core.authentication.auth.jwt.JwtUtils;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsImpl;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsServiceImpl;
import de.panomenal.core.authentication.auxiliary.data.request.LoginRequest;
import de.panomenal.core.authentication.auxiliary.data.request.RegisterRequest;
import de.panomenal.core.authentication.auxiliary.data.request.TwoFASetupRequest;
import de.panomenal.core.authentication.auxiliary.data.response.JwtResponse;
import de.panomenal.core.authentication.auxiliary.data.response.LogoutResponse;
import de.panomenal.core.authentication.auxiliary.data.response.SignUpResponse;
import de.panomenal.core.authentication.auxiliary.data.response.TwoFAResponse;
import de.panomenal.core.authentication.auxiliary.data.response.VerifyResponse;
import de.panomenal.core.authentication.auxiliary.exceptions.types.AuthenticationException;
import de.panomenal.core.authentication.auxiliary.exceptions.types.Invalid2FACodeException;
import de.panomenal.core.authentication.auxiliary.exceptions.types.TokenException;
import de.panomenal.core.authentication.auxiliary.exceptions.types.TwoFAException;
import de.panomenal.core.authentication.role.ERole;
import de.panomenal.core.authentication.token.TokenService;
import de.panomenal.core.authentication.user.UserService;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;

@Controller
@RequestMapping(path = AppConstants.AUTH_URL)
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    TokenService tokenService;

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

    // TODO: switch to RequestParam???
    // TODO: use auth filter to get userdetailsimpl and save authendicated not in
    // token???

    @PostMapping(AppConstants.LOGIN_PATH)
    public ResponseEntity<JwtResponse> loginRequest(@Valid @RequestBody LoginRequest loginRequest) {
        authenticate(loginRequest.getUsername(), loginRequest.getPassword());

        // TODO: handle brute force

        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
        boolean twoFAAuthentication = userDetails.isUsing2FA();
        boolean isAuthenticated = !twoFAAuthentication;

        String jwtToken = jwtUtils.generateToken(userDetails, isAuthenticated);

        if (twoFAAuthentication) {
            tokenService.addTwoFAToken(jwtToken);
        }

        String role = userDetails.getAuthority().getAuthority();

        return ResponseEntity.ok(new JwtResponse(jwtToken, userDetails.getId(), userDetails.getUsername(),
                userDetails.getEmail(), role, isAuthenticated));
    }

    @PostMapping(AppConstants.REGISTER_PATH)
    public ResponseEntity<SignUpResponse> registerRequest(@Valid @RequestBody RegisterRequest registerRequest) {
        userService.registerUser(registerRequest);
        return ResponseEntity.ok(new SignUpResponse(true));
    }

    @PostMapping(AppConstants.VERIFY_PATH)
    public ResponseEntity<VerifyResponse> verifyRequest(@NotEmpty HttpServletRequest request) {
        final String accessToken = getTokenFromRequest(request);

        if (tokenService.isTwoFAToken(accessToken)) {
            throw new TokenException("Token is a 2FA-Token");
        } else if (tokenService.isOnBlacklist(accessToken)) {
            throw new TokenException("Token is on Blacklist");
        } else {
            // Throws exception if e.g. the token is expired
            String username = jwtUtils.getUsernameFromToken(accessToken);

            if (username != null) {
                UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(username);
                if (jwtUtils.validateToken(accessToken, userDetails)) {
                    // Is Valid token
                    List<GrantedAuthority> authorities = jwtUtils.isAuthenticated(accessToken)
                            ? (List<GrantedAuthority>) userDetails.getAuthorities()
                            : List.of(new SimpleGrantedAuthority(ERole.ROLE_PRE_VERIFICATION_USER.name()));
                    return ResponseEntity
                            .ok(new VerifyResponse("Ok", jwtUtils.isAuthenticated(accessToken), username, authorities));
                }
            }
            return ResponseEntity.badRequest().body(new VerifyResponse("", false, "", new ArrayList<>()));
        }
    }

    @PostMapping(AppConstants.TWO_FA_SETUP)
    public ResponseEntity<TwoFAResponse> setupTwoFA(@NotEmpty @RequestBody TwoFASetupRequest twoFASetupRequest,
            @NotEmpty HttpServletRequest request) throws TwoFAException {
        // TODO: rework that the secret gets stored in redis and this secret is used to
        // Check for valid jwt token
        final String token = getTokenFromRequest(request);
        String username = jwtUtils.getUsernameFromToken(token);

        if (twoFASetupRequest.isEnableTwoFA()) {
            // enable 2fa
            if (twoFASetupRequest.getTwoFACode().isEmpty()) {
                // no code got passed -> setup 2fa
                String secret = userService.generate2FASecret();
                QrData qrData = qrDataFactory.newBuilder().label(username).secret(secret)
                        .issuer(AppConstants.QR_ISSUER).build();

                try {
                    String qrCodeImg = getDataUriForImage(qrGenerator.generate(qrData), qrGenerator.getImageMimeType());
                    return ResponseEntity.ok(new TwoFAResponse(secret, qrCodeImg, false));
                } catch (QrGenerationException e) {
                    e.printStackTrace();
                }

            } else {
                // code got passed -> validate
                if (!verifier.isValidCode(twoFASetupRequest.getTwoFASecret(), twoFASetupRequest.getTwoFACode())) {
                    throw new TwoFAException("Code is invalid");
                } else {
                    userService.enableTwoFA(username, twoFASetupRequest.getTwoFASecret());
                    return ResponseEntity.ok(new TwoFAResponse(true));
                }
            }
        } else {
            // disable 2fa
            userService.disableTwoFA(username);
            return ResponseEntity.ok(new TwoFAResponse(true));
        }
        throw new TwoFAException("An error occurred");
    }

    @PostMapping(AppConstants.VERIFY_TWO_FA_PATH)
    public ResponseEntity<JwtResponse> verifyTwoFARequest(@NotEmpty @RequestBody String twoFACode,
            @NotEmpty HttpServletRequest request) throws Invalid2FACodeException, TokenException {
        final String token = getTokenFromRequest(request);

        if (tokenService.isTwoFAToken(token)) {
            // Throws exception if e.g. the token is expired
            String username = jwtUtils.getUsernameFromToken(token);
            UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(username);

            if (!verifier.isValidCode(userDetails.getSecret(), twoFACode)) {
                throw new Invalid2FACodeException("Invalid Code");
            }
            String jwt = jwtUtils.generateToken(userDetails, false);

            String role = userDetails.getAuthority().getAuthority();

            return ResponseEntity.ok(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    role,
                    true));
        } else {
            throw new TokenException("Token is not a 2FA-Token");
        }
    }

    @PostMapping(AppConstants.REFRESH_PATH)
    public ResponseEntity<JwtResponse> refreshRequest(@NotEmpty HttpServletRequest request) {
        final String token = getTokenFromRequest(request);

        // Throws exception if e.g. the token is expired
        String username = jwtUtils.getUsernameFromToken(token);
        UserDetailsImpl userDetails = userDetailsService.loadUserByUsername(username);

        if (jwtUtils.canTokenBeRefreshed(token) && userDetails.canLogin()) {
            String refreshedToken = jwtUtils.refreshToken(token);
            // Add old token to blacklist
            tokenService.addToBlacklist(token);
            // Send back the new token
            return ResponseEntity.ok(new JwtResponse(refreshedToken));
        }
        return ResponseEntity.badRequest().body(new JwtResponse(null));
    }

    @PostMapping(AppConstants.LOGOUT_PATH)
    public ResponseEntity<?> logoutRequest(@NotEmpty HttpServletRequest request) {
        final String token = getTokenFromRequest(request);
        if (tokenService.isOnBlacklist(token)) {
            throw new TokenException("Token is already on blacklist");
        }
        tokenService.addToBlacklist(token);
        return ResponseEntity.ok(new LogoutResponse(true));
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

    private String getTokenFromRequest(HttpServletRequest request) throws AuthenticationException {
        String authToken = request.getHeader(AppConstants.AUTH_HEADER);

        if (authToken == null) {
            throw new AuthenticationException("You need to provide the JWT Token to access this resource", null);
        }

        return authToken.substring(7);
    }

}
