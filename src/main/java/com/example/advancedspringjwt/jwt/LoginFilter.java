package com.example.advancedspringjwt.jwt;

import com.example.advancedspringjwt.dto.CustomUserDetails;
import com.example.advancedspringjwt.entity.RefreshEntity;
import com.example.advancedspringjwt.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    private final RefreshRepository refreshRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepository =refreshRepository;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공시 실행하는 메소드 (여기서 2개의 토큰을 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        //유저 정보를 authentication에서 꺼내옴
        //username
        String username = authentication.getName();

        //role
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L); //Access토큰은 생명주기가 짧음 (10분)
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L); //Refresh토큰은 생명주기가 긺 (24시간)

        //Refresh토큰 저장
        addRefreshEntity(username, refresh, 86400000L);

        //응답 설정 (응답은 response에 넣어줌)
        response.setHeader("access", access); //Access 토큰은 응답 헤더에 넣어줌
        response.addCookie(createCookie("refresh", refresh)); //Refresh 토큰은 응답 cookie에 넣어줌
        response.setStatus(HttpStatus.OK.value()); //응답 상세코드 설정
    }

    //Refresh토큰을 DB에 저장하는 메소드
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs); //만료일자 만듦

        RefreshEntity refreshEntity = new RefreshEntity(); //Entity만들어서
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity); //저장
    }

    //쿠키 생성 메소드
    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60); //cookie가 살아있을 시간

        //cookie에 대해서 https통신에서만 사용할 수 있음
        //cookie.setSecure(true); //local 환경은 https가 아니기 때문에 주석처리

        //cookie.setPath("/"); //cookie가 보일 위치: 전역
        cookie.setHttpOnly(true); //JavaScript가 해당 쿠키를 가져가지 못하게 함 (접근하지 못하게 함)

        return cookie;
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        //로그인 실패시 401 응답 코드 반환
        response.setStatus(401);
    }
}
