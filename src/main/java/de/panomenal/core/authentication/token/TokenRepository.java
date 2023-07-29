package de.panomenal.core.authentication.token;

import org.springframework.data.repository.CrudRepository;

public interface TokenRepository extends CrudRepository<Token, String> {

}
