package com.chahboune.ibrahim.jwtwithsessions.config;

import com.chahboune.ibrahim.jwtwithsessions.repository.UserRepository;
import com.chahboune.ibrahim.jwtwithsessions.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthentificationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final UserRepository repository;

    @Override
    protected void doFilterInternal
            (
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String jwt;
        final String userEmail;
        final String refreshToken;


        // Extracting the access Token
        jwt = extractAccessToken(request);
        refreshToken = extractRefreshToken(request);
        if(jwt == null || refreshToken == null) {
            filterChain.doFilter(request, response);
            return;
        }


        userEmail = jwtService.extractUsername(jwt);
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt, userDetails)){
                // log error
                int counter = Integer.parseInt(jwtService.getClaimsFromToken(jwt).get("counter").toString());
                if(counter == repository.findByEmail(userEmail).get().getCounter()){
                    setUserToContext(userDetails, request);
                }
            } else if (!jwtService.isTokenValid(jwt,userDetails) && jwtService.isTokenValid(refreshToken,userDetails)){
                if(jwtService.isTokenValid(refreshToken,userDetails)){

                    int counter = Integer.parseInt(jwtService.getClaimsFromToken(refreshToken).get("counter").toString());
                    if(counter == repository.findByEmail(userEmail).get().getCounter()){
                        setUserToContext(userDetails, request);
                        String newAccessToken = jwtService.generateToken(userDetails);
                        response.setHeader("new_access_token", newAccessToken);
                    }
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    private void setUserToContext(UserDetails userDetails, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private String extractAccessToken(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return null;
        } else {
            return authHeader.substring(7);
        }
    }

    private String extractRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refreshToken")) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
