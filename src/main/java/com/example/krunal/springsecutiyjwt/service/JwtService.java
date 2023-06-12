package com.example.krunal.springsecutiyjwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.cglib.core.internal.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
    private static final String SECRET_KEY  = "3a8b3fbcc5e03eb8f5d5e1656d4d9c19860c7536a0009b68f09dbdc2f3e5ea5e";





    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }


    public <T> T extractClaim(String token, Function<Claims, T> claimsTFunction){
        final Claims claims = extraAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    // to extract token
    public Claims extraAllClaims(String jwttoken){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) //
                .build()
                .parseClaimsJws(jwttoken)
                .getBody();
    }

    public Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>() , userDetails);
    }

    public String generateToken(Map<String , Object> extraClaims,
    UserDetails userDetails){
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails
                .getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public boolean isTokenValid(String token , UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    public boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
    public Date extractExpiration(String token){
        return extractClaim(token , Claims::getExpiration);

    }
}
