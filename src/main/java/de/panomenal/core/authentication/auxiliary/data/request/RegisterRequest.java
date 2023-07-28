package de.panomenal.core.authentication.auxiliary.data.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {

    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(min = 6, max = 255)
    private String password;

    private String role;

    @NotBlank
    @Email
    @Size(max = 255)
    private String email;

    @NotBlank
    private boolean using2FA;

    private String twoFACode;
    private String twoFASecret;

}
