package com.chahboune.ibrahim.jwtwithsessions.service;

import com.chahboune.ibrahim.jwtwithsessions.constants.Constants;
import com.chahboune.ibrahim.jwtwithsessions.model.User;
import com.chahboune.ibrahim.jwtwithsessions.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    @Autowired
    private Environment env;

    @Autowired
    private UserRepository userRepository;


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        claims.put("type","access");
        claims.put("counter", userRepository.findByEmail(userDetails.getUsername()).get().getCounter());
        return generateToken(claims, userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        final String ACCESS_TOKEN_VALIDITY_SECONDS = env.getProperty("ACCESS_TOKEN_VALIDITY_SECONDS");
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + Integer.parseInt(ACCESS_TOKEN_VALIDITY_SECONDS) * 1000);

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expirationTime)
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        claims.put("counter", userRepository.findByEmail(userDetails.getUsername()).get().getCounter());

        final String REFRESH_TOKEN_VALIDITY_SECONDS = env.getProperty("REFRESH_TOKEN_VALIDITY_SECONDS");

        String refreshToken = Jwts
                .builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + Integer.parseInt(REFRESH_TOKEN_VALIDITY_SECONDS) * 1000))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

        return refreshToken;
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // method to get the claims from the token
    public Claims getClaimsFromToken(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(env.getProperty("security_key"));
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
