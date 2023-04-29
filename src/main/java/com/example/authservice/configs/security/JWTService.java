package com.example.authservice.configs.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

import static com.example.authservice.constants.AppConstant.ACCESS_TOKEN_TIMEOUT_MINUTE;

@Service
public class JWTService {

    private final String SECRET_KEY = "792F423F4428472B4B6250655368566D597133743677397A244326462948404D63516" +
            "6546A576E5A7234753778214125442A472D4B614E645267556B58703273357638792F423F4528482B4D625165536856" +
            "6D597133743677397A24432646294A404E635266556A576E5A7234753778214125442A472D4B6150645367566B59703" +
            "273357638792F423F4528482B4D6251655468576D5A7134743677397A24432646294A404E635266556A586E32723575" +
            "3878214125442A472D4B6150645367566B597033733676397924423F4528482B4D6251655468576D5A7134743777217" +
            "A25432A46294A404E635266556A586E3272357538782F413F4428472B4B6150645367566B5970337336763979244226" +
            "452948404D6351655468576D5A7134743777217A25432A462D4A614E645267556A586E3272357538782F413F4428472" +
            "B4B6250655368566D5970337336763979244226452948404D635166546A576E5A7234743777217A25432A462D4A614E" +
            "645267556B58703273357638792F413F4428472B4B6250655368566D597133743677397A244326452948404D6351665" +
            "46A576E5A7234753778214125442A472D4A614E645267556B58703273357638792F423F4528482B4D6250655368566D" +
            "597133743677397A24432646294A404E635266546A576E5A7234753778214125442A472D4B6150645367566B5870327" +
            "33576";

//    private final String SECRET_KEY = "5367566B5970337336763979244226452948404D6351655468576D5A7134743777217A25432A462D4A614E645267556A586E3272357538782F413F4428472B4B6250655368566D5970337336763979244226452948404D635166546A576E5A7234743777217A25432A462D4A614E645267556B58703273357638782F413F4428472B4B6250655368566D597133743677397A244226452948404D635166546A576E5A7234753778214125442A462D4A614E645267556B58703273357638792F423F4528482B4B6250655368566D597133743677397A24432646294A404E635166546A576E5A7234753778214125442A472D4B6150645367556B58703273357638792F423F4528482B4D6251655468576D597133743677397A24432646294A404E635266556A586E327235753778214125442A472D4B6150645367566B59703373367639792F423F4528482B4D6251655468576D5A7134743777217A25432646294A404E635266556A586E3272357538782F413F4428472D4B6150645367566B5970337336763979244226452948404D6251655468576D5A7134743777217A25432A462D4A614E645266556A586E3272357538782F413F4428472B4B6250655368566B5970337336763979244226452948404D635166546A576E5A7134743777217A25432A462D4A614E645267556B58703273357538782F413F4428472B4B6250";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<String> extractRoles(String token) {
        final Claims claims = extractAllClaims(token);
        return (List<String>) claims.get("roles");
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
//        System.out.println("Roles extracted: " + extractRoles(token));
        return extractUsername(token).equals(userDetails.getUsername()) &&
                !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails, long timeout) {
        Map<String, Object> extraClaims = new HashMap<>();
        List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        extraClaims.put("roles", roles);
        return generateToken(extraClaims, userDetails, timeout);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, long timeout) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + timeout * 60 * 1000))
                .signWith(createSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(createSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key createSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
