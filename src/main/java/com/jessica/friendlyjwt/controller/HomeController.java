package com.jessica.friendlyjwt.controller;

import com.jessica.friendlyjwt.model.User;
import com.jessica.friendlyjwt.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class HomeController {

    Logger logger = LoggerFactory.getLogger(HomeController.class);


    @GetMapping("/home")
    public String homepage(Authentication authentication){
        var user = authentication.getPrincipal();
        logger.info("Here is the user principle : {}", authentication.getPrincipal());
        logger.info("Here is the user Credential : {}", authentication.getCredentials());
        logger.info("Here is the user Detail : {}", authentication.getDetails());
        logger.info("Here is the user Authorities : {}", authentication.getAuthorities());
        return "Hello "+ authentication.getName();
    }
}
