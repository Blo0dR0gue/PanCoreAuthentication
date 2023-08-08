package de.panomenal.core.authentication.auxiliary.data.request;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class TwoFASetupRequest {

    private boolean enableTwoFA;

    private String twoFACode;
    private String twoFASecret;

}
