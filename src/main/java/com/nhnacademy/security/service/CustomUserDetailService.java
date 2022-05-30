package com.nhnacademy.security.service;

import com.nhnacademy.security.entity.Authorotiy;
import com.nhnacademy.security.entity.Member;
import com.nhnacademy.security.repository.AuthorotiyRepository;
import com.nhnacademy.security.repository.MemberRepository;
import java.util.Collections;
import java.util.Objects;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("customUserDetailService")
public class CustomUserDetailService implements UserDetailsService {

    private final MemberRepository repository;
    private final AuthorotiyRepository authrepository;

    public CustomUserDetailService(MemberRepository repository, AuthorotiyRepository authrepository) {
        this.repository = repository;
        this.authrepository = authrepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = repository.findById(username).orElseThrow(NullPointerException::new);
        if (Objects.isNull(member)) {
            return null;
        }

        Authorotiy authorotiy = authrepository.findById(username).orElseThrow(NullPointerException::new);
        SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authorotiy.getAuthority());

        return new User(member.getMemberId(), member.getPw(), Collections.singletonList(grantedAuthority));
    }
}
