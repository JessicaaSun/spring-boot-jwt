package com.jessica.friendlyjwt.service.serviceImpl;

import com.jessica.friendlyjwt.model.User;
import com.jessica.friendlyjwt.repository.UserRepository;
import com.jessica.friendlyjwt.service.UserService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    UserRepository userRepository;
    UserServiceImpl(UserRepository userRepository){
        this.userRepository =userRepository;
    }
    @Override
    public List<User> findUserByName(String username) {
        return userRepository.findUserByName(username);
    }

}
