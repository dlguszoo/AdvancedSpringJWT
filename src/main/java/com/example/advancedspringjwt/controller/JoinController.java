package com.example.advancedspringjwt.controller;

import com.example.advancedspringjwt.dto.JoinDto;
import com.example.advancedspringjwt.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {
    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinPorcess(JoinDto joinDto) {
        joinService.joinProcess(joinDto);
        return "ok";
    }
}
