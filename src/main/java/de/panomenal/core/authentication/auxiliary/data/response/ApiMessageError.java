package de.panomenal.core.authentication.auxiliary.data.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
public class ApiMessageError extends ApiSubError {

    private String message;

}
