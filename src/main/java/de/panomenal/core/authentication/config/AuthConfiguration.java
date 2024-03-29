package de.panomenal.core.authentication.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import de.panomenal.core.authentication.AppConstants;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true // Allow role check on method entry
)
public class AuthConfiguration {

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        // Setup the encoder for passwords
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        // Setting up auth manager
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(handling -> handling.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        .antMatchers(HttpMethod.OPTIONS, AppConstants.API_URL_PATTERN).permitAll() // allows preflights
                        .antMatchers(HttpMethod.POST, AppConstants.AUTH_URL_PATTERN).permitAll() // allows authorization
                        .antMatchers(AppConstants.API_URL_PATTERN).hasAnyRole("ADMIN", "USER") // block everything else
                        .anyRequest().authenticated());

        return http.build();
    }

}
