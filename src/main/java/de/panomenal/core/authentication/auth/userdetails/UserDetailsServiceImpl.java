package de.panomenal.core.authentication.auth.userdetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import de.panomenal.core.authentication.user.UserRepository;
import jakarta.transaction.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetailsImpl loadUserByUsername(String username) throws UsernameNotFoundException {
        return UserDetailsImpl.build(
                userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username)));
    }

}
