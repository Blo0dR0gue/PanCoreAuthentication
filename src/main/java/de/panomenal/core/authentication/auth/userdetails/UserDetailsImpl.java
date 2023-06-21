package de.panomenal.core.authentication.auth.userdetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

import de.panomenal.core.authentication.user.User;

/**
 * Implementation of the UserDetails interface
 */
public class UserDetailsImpl implements UserDetails {

    private int id;

    private String username;

    private String email;

    private boolean enabled;

    private boolean using2FA;

    /**
     * 2FA-Secret if using 2FA
     */
    private String secret;

    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(int id, String username, String email, String password, boolean enabled, boolean using2FA,
            Collection<? extends GrantedAuthority> authorities, String secret) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.password = password;
        this.enabled = enabled;
        this.using2FA = using2FA;
        this.authorities = authorities;
        this.secret = secret;
    }

    public static UserDetailsImpl build(User user) {
        /*
         * List<GrantedAuthority> authorities = user.getRoles().stream()
         * .map(role -> new SimpleGrantedAuthority(role.getName().name()))
         * .collect(Collectors.toList());
         */
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(user.getRole().getName().name()));

        return new UserDetailsImpl(user.getId(), user.getUsername(), user.getEmail(), user.getPassword(),
                user.isEnabled(), user.isUsing2FA(), authorities, user.getSecret());
    };

    public int getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public boolean isUsing2FA() {
        return using2FA;
    }

    public String getSecret() {
        return secret;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // TODO: ??
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // TODO: ??
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // TODO: ??
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }

}