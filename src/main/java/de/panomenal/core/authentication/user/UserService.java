package de.panomenal.core.authentication.user;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import de.panomenal.core.authentication.auxiliary.data.request.RegisterRequest;
import de.panomenal.core.authentication.auxiliary.exceptions.types.TwoFAException;
import de.panomenal.core.authentication.auxiliary.exceptions.types.UserAlreadyExistAuthenticationException;
import de.panomenal.core.authentication.role.ERole;
import de.panomenal.core.authentication.role.Role;
import de.panomenal.core.authentication.role.RoleRepository;
import dev.samstevens.totp.secret.SecretGenerator;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    @Autowired
    private SecretGenerator secretGenerator;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public String generate2FASecret() {
        return secretGenerator.generate();
    }

    public void checkIfUserExists(String username, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new UserAlreadyExistAuthenticationException(
                    "User with Username: " + username + " already exist");
        }

        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistAuthenticationException(
                    "User with E-Mail: " + email + " already exist");
        }
    }

    public User registerUser(RegisterRequest requestData) {
        this.checkIfUserExists(requestData.getUsername(), requestData.getEmail());

        // Create new user's account
        User user = new User(requestData.getUsername(),
                requestData.getEmail(),
                passwordEncoder.encode(requestData.getPassword()));

        user.setEnabled(true);

        String strRole = requestData.getRole();
        Role role = null;

        // TODO: Rework this logic
        if (strRole == null) {
            role = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role not found."));
        } else {
            switch (strRole) {
                case "admin":
                    role = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role not found."));
                    break;
                default:
                    role = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role not found."));
            }
        }

        user.setRole(role);
        userRepository.save(user);
        return user;
    }

    public User enableTwoFA(String username, String secret) throws TwoFAException {
        Optional<User> optional = userRepository.findByUsername(username);
        if (optional.isPresent()) {
            User user = optional.get();
            user.setUsing2FA(true);
            user.setSecret(secret);
            userRepository.save(user);
            return user;
        } else {
            throw new TwoFAException("Username " + username + " not found");
        }
    }

    public User disableTwoFA(String username) {
        Optional<User> optional = userRepository.findByUsername(username);
        if (optional.isPresent()) {
            User user = optional.get();
            user.setUsing2FA(false);
            user.setSecret("");
            userRepository.save(user);
            return user;
        } else {
            throw new TwoFAException("Username " + username + " not found");
        }
    }

}
