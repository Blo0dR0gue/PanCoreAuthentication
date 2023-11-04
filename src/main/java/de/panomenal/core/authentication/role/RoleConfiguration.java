package de.panomenal.core.authentication.role;

import java.util.Optional;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RoleConfiguration {

    /**
     * Create all roles
     * 
     * @param roleRepository
     * @return args
     */
    @Bean
    CommandLineRunner commandLineRunner(RoleRepository roleRepository) {
        return args -> {
            for (ERole role : ERole.values()) {
                Optional<Role> optRole = roleRepository.findByName(role);
                if (optRole.isEmpty()) {
                    roleRepository.save(new Role(role));
                }
            }
        };
    }
}
