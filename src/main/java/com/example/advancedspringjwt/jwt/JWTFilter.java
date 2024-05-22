package com.example.advancedspringjwt.jwt;

import com.example.advancedspringjwt.dto.CustomUserDetails;
import com.example.advancedspringjwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    //JWTUtil을 통해 필터 검증 메소드를 가져와야 하므로
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    //jwt를 request에서 뽑아내어 검증 진행
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization");

        //Authorization 헤더 검증 (토큰이 없는지, Bearer이라는 접두사를 가지는지 확인)
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");
            filterChain.doFilter(request, response); //true면 doFilter을 통해 <- 옆의 필터를 종료하고, 파라미터로 받은 request와 response를 다음 필터로 넘겨준다.

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }
        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) { //JWTUtill에서 구현한 메소드

            System.out.println("token expired");
            filterChain.doFilter(request, response); //true면 doFilter을 통해 <- 옆의 필터를 종료하고, 파라미터로 받은 request와 response를 다음 필터로 넘겨준다.

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰이 존재하고, 소멸시간도 지나지 않으면 토큰 유효함이 확인됨
        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); //비밀번호 값의 경우, 토큰에 담겨 있지 않았음 -> 비밀번호 값은 초기화 (매번 DB 들락날락하지 않기 위해서 임시적인 비번 하나 만듦. SecurityContextHolder에 정확한 비번 넣을 필요 없음)
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        //메소드 종료됐으므로 그 다음 필터로 넘김
        filterChain.doFilter(request, response);
    }
}
