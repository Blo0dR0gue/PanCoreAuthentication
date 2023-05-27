package de.panomenal.core.authentication.auxiliary.exceptions;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import de.panomenal.core.authentication.auxiliary.data.response.ApiErrorResponse;
import jakarta.persistence.EntityNotFoundException;

@ControllerAdvice
public class ExceptionController extends ResponseEntityExceptionHandler {

    @Override
    @Nullable
    protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return buildErrorResponse(ex,
                String.format("Could not found the %s method for URL %s", ex.getHttpMethod(), ex.getRequestURL()),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(EntityNotFoundException.class)
    protected ResponseEntity<Object> handleEntityNotFoundException(EntityNotFoundException ex) {
        return buildErrorResponse(ex, "Entity not found", HttpStatus.NOT_FOUND);
    }

    /**
     * Creates a {@link ResponseEntity} including an {@link ApiErrorResponse}.
     * 
     * @param exception  The {@link Exception} object
     * @param message    The message, which should be displayed
     * @param httpStatus The {@link HttpStatus}-code for this response.
     * @return A {@link ResponseEntity}
     */
    private ResponseEntity<Object> buildErrorResponse(
            Exception exception,
            String message,
            HttpStatus httpStatus) {
        ApiErrorResponse errorResponse = new ApiErrorResponse(httpStatus.value(), message, exception.getMessage());

        return ResponseEntity.status(httpStatus).body(errorResponse);
    }

}
