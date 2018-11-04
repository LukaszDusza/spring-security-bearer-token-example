package com.auth0.security;

import com.auth0.jwt.JWT;
import com.auth0.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.IOException;
import java.util.*;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.auth0.security.SecurityConstants.EXPIRATION_TIME;
import static com.auth0.security.SecurityConstants.HEADER_STRING;
import static com.auth0.security.SecurityConstants.SECRET;
import static com.auth0.security.SecurityConstants.TOKEN_PREFIX;

//Ta klasa UsernamePasswordAuthenticationFilter, jest dostarczana przez Spring Security.
// Rejestruje się jako filtr odpowiedzialny za punkt końcowy '/login'.
// W związku z tym, za każdym razem, gdy backend API dostaje żądanie do /login, filtr ten  (tj. JWTAuthenticationFilter)
// wchodzi w działanie i obsługuje próbę uwierzytelnienia (metodą attemptAuthentication).

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    //tu wpada zapytanie z '/login'.

    @Override
    public Authentication attemptAuthentication (
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {

        try {
            User user = new ObjectMapper()
                    .readValue(request.getInputStream(), User.class);
            //getInputStream() - wyciąga ciało z zawartości zapytania POST i parsuje na klasę User.

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            user.getPassword(),
                            new ArrayList<>()) /*Granted Authority - role */
            );


        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain,
                                            Authentication auth) throws IOException, ServletException {

        String token = JWT.create()
                .withSubject(((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.getBytes()));
        response.addHeader("access-control-expose-headers", "Authorization");
        response.addHeader("access-control-expose-headers", "User");
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
        response.addHeader("User", ((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername());


        System.out.println(response.getHeader("Authorization"));

    }

}
