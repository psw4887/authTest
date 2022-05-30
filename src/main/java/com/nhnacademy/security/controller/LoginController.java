package com.nhnacademy.security.controller;

import com.nhnacademy.security.service.LoginService;
import com.nhnacademy.security.vo.User;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    private final LoginService service;

    public LoginController(LoginService service) {
        this.service = service;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String doLogin(@RequestParam("id")String id,
                          @RequestParam("pw")String pw,
                          HttpServletRequest request) {
        if(service.isMemberExist(id, pw)) {
            HttpSession session = request.getSession();
            User user = new User(id, pw);
            session.setAttribute("user", user);
            return "redirect:/";
        }
        return "redirect:/login";
    }

}
