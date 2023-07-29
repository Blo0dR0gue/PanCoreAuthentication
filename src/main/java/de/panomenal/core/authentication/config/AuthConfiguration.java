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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import de.panomenal.core.authentication.AppConstants;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true // Allow role check on method entry
)
public class AuthConfiguration {

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

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Autowired
    private AuthTokenFilter authenticationJwtTokenFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, AppConstants.API_URL_PATTERN).permitAll() // allows preflights for
                                                                                           // secured urls
                .antMatchers(HttpMethod.POST, AppConstants.AUTH_URL_PATTERN).permitAll() // allows authorization
                .antMatchers(AppConstants.API_URL_PATTERN).hasAnyRole("ADMIN", "USER") // secures all rest api urls
                .antMatchers("/**").permitAll() // allows all other urls
                .anyRequest().authenticated();

        // http.addFilterBefore(exceptionHandlerFilter,
        // UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(authenticationJwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
