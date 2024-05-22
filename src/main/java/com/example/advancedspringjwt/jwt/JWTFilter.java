package com.example.advancedspringjwt.jwt;

import com.example.advancedspringjwt.dto.CustomUserDetails;
import com.example.advancedspringjwt.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

public class JWTFilter extends OncePerRequestFilter {

    //JWTUtil을 통해 필터 검증 메소드를 가져와야 하므로
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    //jwt를 request에서 뽑아내어 검증 진행
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 access키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {

            filterChain.doFilter(request, response); //다음 필터로 넘김

            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) { //만료됐으면 오류가 던져짐. -> ExpiredJwtException으로 받음

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired"); //응답메시지: "토큰이 만료되었다"

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); //특정 상태코드를 보내줌 (프론트 측과 협의)
            //중요: 다음 필터로 넘기지 않고 응답 코드만 발생시킴.
            return;
        }

        // 토큰이 access인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken); //카테고리값 꺼냄

        if (!category.equals("access")) { //Access토큰이 아니면

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token"); //응답메시지: "Access토큰이 아니다"

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); //특정 상태코드를 보내줌 (프론트 측과 협의)
            //중요: 다음 필터로 넘기지 않고 응답 코드만 발생시킴.
            return;
        }

        // 토큰 내부에서 username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity); //userEntity로 UserDetails 만듦

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities()); //로그인 진행
        SecurityContextHolder.getContext().setAuthentication(authToken); //SecurityContextHolder에 유저 등록시켜 일시적인 세션 만들어짐

        filterChain.doFilter(request, response);
    }
}
