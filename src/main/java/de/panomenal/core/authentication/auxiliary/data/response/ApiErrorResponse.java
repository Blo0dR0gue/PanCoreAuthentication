package de.panomenal.core.authentication.auxiliary.data.response;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;

import de.panomenal.core.authentication.auxiliary.resolver.LowerCaseClassNameResolver;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
@JsonTypeInfo(include = JsonTypeInfo.As.WRAPPER_OBJECT, use = JsonTypeInfo.Id.CUSTOM, property = "error", visible = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonTypeIdResolver(LowerCaseClassNameResolver.class)
public class ApiErrorResponse {
    private final int status;
    private final String message;
    private final String debugMessage;
    private List<ApiSubError> subErrors;

    public ApiErrorResponse(int status, String message, String debugMessage) {
        this.status = status;
        this.message = message;
        this.debugMessage = debugMessage;
    }

    public void addSubError(ApiSubError subError) {
        if (this.subErrors == null) {
            this.subErrors = new ArrayList<>();
        }
        this.subErrors.add(subError);
    }

    public void addSubErrors(Collection<ApiSubError> subErrors) {
        if (this.subErrors == null) {
            this.subErrors = new ArrayList<>();
        }
        this.subErrors.addAll(subErrors);
    }

}