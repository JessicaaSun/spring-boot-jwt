package com.jessica.friendlyjwt.model.response;

import com.jessica.friendlyjwt.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    private String AccessToken;
//    private User user;
    private String tokenType;
}
