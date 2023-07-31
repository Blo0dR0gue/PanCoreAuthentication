package de.panomenal.core.authentication.auxiliary.data.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
@AllArgsConstructor
public class LogoutResponse {

    private boolean successful;

}
