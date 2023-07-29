package de.panomenal.core.authentication.auxiliary.data.request;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

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

    @NotNull
    private boolean using2FA;

    private String twoFACode;
    private String twoFASecret;

}
