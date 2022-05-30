package com.nhnacademy.security.service;

import com.nhnacademy.security.repository.MemberRepository;
import org.springframework.stereotype.Service;

@Service("loginService")
public class LoginService {
    private final MemberRepository repository;

    public LoginService(MemberRepository repository) {
        this.repository = repository;
    }

    public boolean isMemberExist(String id, String pw) {
        return repository.existsByMemberIdAndPw(id, pw);
    }
}
