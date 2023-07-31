package de.panomenal.core.authentication.token;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService {

    @Autowired
    private TokenRepository tokenRepository;

    public boolean isTwoFAToken(String jwtToken) {
        Optional<Token> token = tokenRepository.findById(jwtToken);
        if (token.isPresent()) {
            return token.get().isTwoFAToken();
        }
        return false;
    }

    public boolean isOnBlacklist(String jwtToken) {
        Optional<Token> token = tokenRepository.findById(jwtToken);
        return token.isPresent();
    }

    public void addToBlacklist(String jwtToken) {
        tokenRepository.save(new Token(jwtToken, false));
    }

    public void addTwoFAToken(String jwtToken) {
        tokenRepository.save(new Token(jwtToken, true));
    }

}
