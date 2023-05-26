package com.jessica.friendlyjwt.controller;

import com.jessica.friendlyjwt.model.request.LoginRequest;
import com.jessica.friendlyjwt.model.response.LoginResponse;
import com.jessica.friendlyjwt.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AuthenticationController {

    private final TokenService tokenService;
    private final AuthenticationProvider authenticationProvider;
    public AuthenticationController( AuthenticationProvider authenticationProvider, TokenService tokenService){
        this.tokenService=tokenService;
        this.authenticationProvider = authenticationProvider;
    }
//    @PostMapping("/token")
//    public String getToken(Authentication authentication){
//        String token = tokenService.generateToken(authentication);
//        return token;
//    }
    @GetMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest){
    Authentication authentication = new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername()
            ,loginRequest.getPassword()
    );
    authentication = authenticationProvider.authenticate(authentication);

    // JWT
    LoginResponse response = new LoginResponse();
    String token = tokenService.generateToken(authentication);
    response.setAccessToken(token);
    response.setTokenType("Bearer");
    return response;

}
}
