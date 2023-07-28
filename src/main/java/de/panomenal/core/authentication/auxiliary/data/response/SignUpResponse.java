package de.panomenal.core.authentication.auxiliary.data.response;

import lombok.Value;

@Value
public class SignUpResponse {

    private boolean using2FA;

    private String qrCodeImage;

    private String secret;

    private boolean signupDone;

}
