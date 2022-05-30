package com.nhnacademy.security.controller;

import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LogoutController {
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        if (Objects.isNull(request.getSession(false))) {
            return "redirect:/";
        }
        request.getSession(false).invalidate();
        return "redirect:/";
    }

}
