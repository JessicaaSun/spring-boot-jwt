package com.jessica.friendlyjwt.repository;

import com.jessica.friendlyjwt.model.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;


import java.util.List;

@Mapper
@Repository
public interface UserRepository {
    @Results({
            @Result(property = "password", column = "secret_key"),
            @Result(column = "id", property = "userId")
    })
    @Select("select * from users_tb where username like #{username}")
    List<User> findUserByName(String username);
}
