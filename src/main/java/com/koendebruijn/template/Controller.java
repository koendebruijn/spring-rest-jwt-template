package com.koendebruijn.template;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class Controller {

    @GetMapping("")
    public String hello() {
        return "User method";
    }

    @GetMapping("/admin")
    public String helloAdmin() {
        return "Admin method";
    }


}
