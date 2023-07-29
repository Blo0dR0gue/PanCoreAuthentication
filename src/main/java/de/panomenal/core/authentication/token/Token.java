package de.panomenal.core.authentication.token;

import java.io.Serializable;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash("Token")
public class Token implements Serializable {

    @Id
    private String token;

    private boolean disabled;
}
