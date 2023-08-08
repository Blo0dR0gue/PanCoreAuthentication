package de.panomenal.core.authentication.auxiliary.data.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
@AllArgsConstructor
public class TwoFAResponse {

    private String secret;

    private String qrCode;

    private boolean setupDone;

    public TwoFAResponse(boolean setupDone) {
        this.setupDone = setupDone;
    }

}
