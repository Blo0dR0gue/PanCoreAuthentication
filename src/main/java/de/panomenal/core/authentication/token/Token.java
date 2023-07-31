package de.panomenal.core.authentication.token;

import java.io.Serializable;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@RedisHash("Token")
@Getter
@Setter
@AllArgsConstructor
public class Token implements Serializable {

    @Id
    private String token;

    private boolean twoFAToken;
}
