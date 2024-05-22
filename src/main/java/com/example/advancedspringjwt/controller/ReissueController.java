package com.example.advancedspringjwt.controller;

import com.example.advancedspringjwt.entity.RefreshEntity;
import com.example.advancedspringjwt.jwt.JWTUtil;
import com.example.advancedspringjwt.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

@Controller
@ResponseBody
public class ReissueController {

    private final JWTUtil jwtUtil;

    private final RefreshRepository refreshRepository;

    public ReissueController(JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) { //제너릭 방식 사용. 인자로는 앞단에서 오는 요청을 받는 HttpServletRequest, 컨트롤러에서 특정 응답을 내려줄 수 있는 HttpServletResponse.

        //get refresh token
        String refresh = null; //Refresh토큰 받을 변수
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) { //모든 쿠키값을 순회해서

            if (cookie.getName().equals("refresh")) { //쿠키 중 refresh라는 키값이 있는지 확인

                refresh = cookie.getValue(); //있으면 값 저장
            }
        }

        if (refresh == null) { //Refresh토큰이 없는가?

            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST); //없으면 특정 상태코드와 메시지 응답 (프론트 측과 합의)
        }

        //Refresh토큰 존재
        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) { //만료되었다면 예외 터짐 -> ExpiredJwtException로 받음

            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST); //만료되었으면 특정 상태코드와 메시지 응답 (프론트 측과 합의)
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh); //카테고리값을 꺼내서 확인

        if (!category.equals("refresh")) { //아니면

            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST); //아니면 특정 상태코드와 메시지 응답 (프론트 측과 합의)
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) { //DB에 없다면

            //response body
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST); //특정 상태코드와 메시지 응답 (프론트 측과 합의)
        }

        String username = jwtUtil.getUsername(refresh); //username 꺼내기
        String role = jwtUtil.getRole(refresh); //role 꺼내기

        //make new Access, Refresh 토큰
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, newRefresh, 86400000L);

        response.setHeader("access", newAccess); //Access토큰은 header에 새로운 Access토큰 넣어서 response
        response.addCookie(createCookie("refresh", newRefresh)); //Refresh토큰은 쿠키를 만들어서 response

        return new ResponseEntity<>(HttpStatus.OK); //200 OK 코드와 함께
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
