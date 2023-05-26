package com.jessica.friendlyjwt.service;

import com.jessica.friendlyjwt.model.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UserService {
    List<User> findUserByName(String username);
}
