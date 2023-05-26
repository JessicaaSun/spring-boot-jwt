package com.jessica.friendlyjwt.service.serviceImpl;

import com.jessica.friendlyjwt.model.User;
import com.jessica.friendlyjwt.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    //load user form the database
    // inject repository
    UserRepository userRepository;
    public UserDetailServiceImpl(UserRepository userRepository){
        this.userRepository = userRepository;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Optional<Object> -> prevent null pointer exception
        User authenticatedUser = userRepository.findUserByName(username).stream().findFirst().orElse(null);
        System.out.println("Here is the authenticatedUser : "+authenticatedUser);
        if(authenticatedUser==null){
            throw new UsernameNotFoundException("AuthenticatedUser doesn't exist");
        }
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        List<SimpleGrantedAuthority> authorities = Collections.singletonList(authority);
        // create an object of user detail type
        org.springframework.security.core.userdetails.User user = (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User.builder()
                .username(authenticatedUser.getUsername())
                .password(authenticatedUser.getPassword())
                .authorities(authorities)
                .build();

        return user;
    }
}
