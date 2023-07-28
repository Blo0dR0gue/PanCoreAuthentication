package de.panomenal.core.authentication.auth.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import de.panomenal.core.AppConstants;
import de.panomenal.core.authentication.auth.userdetails.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {

    @Value("${pancore.auth.jwtSecret}")
    private String jwtSecret;

    @Value("${pancore.auth.jwtExpiration}")
    private int jwtExpiration;

    @Value("${pancore.auth.twoFATokenValid}")
    private int twoFATokenValid;

    public String generateToken(UserDetailsImpl userDetails, boolean twoFAAuthentication) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(AppConstants.TWO_FA_AUTHENTICATION, twoFAAuthentication);
        return doGenerateToken(claims, userDetails.getUsername(), twoFAAuthentication);
    }

    public Boolean canTokenBeRefreshed(String token) {
        return (!isTokenExpired(token));
    }

    public String refreshToken(String token) {
        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate, false);

        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

        final Claims claims = getAllClaimsFromToken(token);
        claims.setIssuedAt(createdDate);
        claims.setExpiration(expirationDate);

        return Jwts.builder().setClaims(claims).signWith(key, SignatureAlgorithm.HS512).compact();
    }

    public Boolean validateToken(String token, UserDetailsImpl userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public Boolean isAuthenticated(String token) {
        return this.getAllClaimsFromToken(token).get(AppConstants.TWO_FA_AUTHENTICATION, Boolean.class);
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
        return Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject, Boolean twoFAAuthentication) {
        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate, twoFAAuthentication);

        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(createdDate)
                .setExpiration(expirationDate).signWith(key, SignatureAlgorithm.HS512).compact();
    }

    private Date calculateExpirationDate(Date createdDate, Boolean twoFAAuthentication) {
        int expirationTime = twoFAAuthentication ? twoFATokenValid * 1000 : jwtExpiration * 1000;
        return new Date(createdDate.getTime() + expirationTime);
    }

}
