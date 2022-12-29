package com.authorization.common.config.authentication.controller;

import com.authorization.common.config.authentication.model.request.AuthorizationRefreshRequest;
import com.authorization.common.config.authentication.model.request.AuthorizationRequest;
import com.authorization.common.config.authentication.model.response.AuthorizationResponse;
import com.authorization.common.config.authentication.model.transfer.UserDetailsImpl;
import com.authorization.common.config.error.errorCode.MemberErrorCode;
import com.authorization.common.config.error.exception.AuthenticationFailedException;
import com.authorization.common.config.error.validator.MemberValidator;
import com.authorization.common.config.filter.StatelessCSRFFilter;
import com.authorization.common.config.handler.UserServiceHandler;
import com.authorization.common.config.jwt.JwtProvider;
import com.authorization.common.config.oauth2.model.ClientRegistration;
import com.authorization.common.config.oauth2.model.request.OAuth2AuthorizationRequest;
import com.authorization.common.config.oauth2.model.response.OAuth2AuthorizationResponse;
import com.authorization.common.config.oauth2.model.response.OAuth2Token;
import com.authorization.common.config.oauth2.model.response.userInfo.OAuth2UserInfo;
import com.authorization.common.config.oauth2.repository.ClientRegistrationRepository;
import com.authorization.common.config.oauth2.repository.InMemoryOAuth2RequestRepository;
import com.authorization.common.config.properties.JwtProperties;
import com.authorization.domain.member.service.query.MemberQueryService;
import com.authorization.common.config.oauth2.service.OAuth2Service;
import com.authorization.common.config.oauth2.service.OAuth2ServiceFactory;
import com.authorization.domain.memberSocial.enums.Provider;
import com.authorization.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final InMemoryOAuth2RequestRepository inMemoryOAuth2RequestRepository;
    private final MemberQueryService memberQueryService;
    private final JwtProvider jwtProvider;
    private final JwtProperties jwtProperties;
    private final RestTemplate restTemplate;
    private final MemberValidator memberValidator;
    private final PasswordEncoder passwordEncoder;
    private final UserServiceHandler userServiceHandler;

    @GetMapping("/csrf-token")
    public ResponseEntity<?> getCsrfToken(HttpServletRequest request, HttpServletResponse response) {


        String encode = passwordEncoder.encode("1234");
        System.out.println("encode = " + encode);

        String csrfToken = UUID.randomUUID().toString();

        Map<String, String> resMap = new HashMap<>();
        resMap.put(StatelessCSRFFilter.CSRF_TOKEN, csrfToken);

        generateCSRFTokenCookie(response);
        return ResponseEntity.ok(resMap);
    }

    /* 사용자의 계정을 인증하고 로그인 토큰을 발급해주는 컨트롤러 */
    @PostMapping("/authorize")
    public ResponseEntity<AuthorizationResponse> authenticateUsernamePassword(
            @RequestBody AuthorizationRequest authorizationRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        memberValidator.authenticateUsernamePassword(authorizationRequest);

        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authorizationRequest.getUsername(), authorizationRequest.getPassword()));
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            String accessToken = generateAccessTokenCookie(userDetails, request, response);
            String refreshToken = generateRefreshTokenCookie(userDetails, request, response);

            generateCSRFTokenCookie(response);

            AuthorizationResponse authorizationResponse = AuthorizationResponse.builder()
                    .access_token(accessToken)
                    .refresh_token(refreshToken)
                    .expires_in(jwtProperties.getAccessTokenExpired())
                    .member_seq(userDetails.getId())
                    .member_id(userDetails.getUsername())
                    .authorities(userDetails.getAuthorities())
                    .build();

            return ResponseEntity.ok().body(authorizationResponse);
        } catch (AuthenticationException e) {
            throw new AuthenticationFailedException(MemberErrorCode.AUTHENTICATION_FAILED);
        }
    }

    @PostMapping("/authorize/refresh")
    public ResponseEntity<AuthorizationResponse> authenticateRefresh(
            @RequestBody AuthorizationRefreshRequest authorizationRefreshRequest,
            HttpServletRequest request,
            HttpServletResponse response) {

        String username = jwtProvider.extractUsernameByRefreshToken(authorizationRefreshRequest.getRefreshToken());
        UserDetailsImpl userDetails = (UserDetailsImpl) userServiceHandler.loadUserByUsername(username);

        //토큰이 유효하다면
        if (jwtProvider.validateRefreshToken(authorizationRefreshRequest.getRefreshToken(), userDetails.getUsername())) {

            String accessToken = generateAccessTokenCookie(userDetails, request, response);
            String refreshToken = generateRefreshTokenCookie(userDetails, request, response);

            AuthorizationResponse authorizationResponse = AuthorizationResponse.builder()
                    .access_token(accessToken)
                    .refresh_token(refreshToken)
                    .expires_in(jwtProperties.getAccessTokenExpired())
                    .member_seq(userDetails.getId())
                    .member_id(userDetails.getUsername())
                    .authorities(userDetails.getAuthorities())
                    .build();

            return ResponseEntity.ok().body(authorizationResponse);
        } else {
            throw new AuthenticationFailedException(MemberErrorCode.INVALID_TOKEN);
        }
    }

    /* 토큰 쿠키를 삭제하는 컨트롤러 (로그아웃) */
    @PostMapping("/logout")
    public ResponseEntity<?> expiredToken(HttpServletRequest request, HttpServletResponse response) {
        CookieUtils.deleteCookie(request, response, "access_token");
        CookieUtils.deleteCookie(request, response, StatelessCSRFFilter.CSRF_TOKEN);
        return ResponseEntity.ok("success");
    }

    /* 사용자의 소셜 로그인 요청을 받아 각 소셜 서비스로 인증을 요청하는 컨트롤러 */
    @GetMapping("/oauth2/authorize/{provider}")
    public void redirectSocialAuthorizationPage(
            @PathVariable Provider provider,
            @RequestParam(name = "redirect_uri") String redirectUri,
            @RequestParam(name = "callback") String callback,
            HttpServletRequest request, HttpServletResponse response
    ) throws Exception {

        String state = generateState();

        // 콜백에서 사용할 요청 정보를 저장
        inMemoryOAuth2RequestRepository.saveOAuth2Request(state, OAuth2AuthorizationRequest.builder().referer(request.getHeader("referer")).redirectUri(redirectUri).callback(callback).build());

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider.getProvider());
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider.getProvider());
        oAuth2Service.redirectAuthorizePage(clientRegistration, state, response);
    }

    /* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @GetMapping("/oauth2/callback/{provider}")
    public void oAuth2AuthenticationCallback(
            @PathVariable Provider provider,
            @ModelAttribute OAuth2AuthorizationResponse oAuth2AuthorizationResponse,
            HttpServletRequest request, HttpServletResponse response,
            @AuthenticationPrincipal UserDetailsImpl loginUser
    ) throws Exception {

        //인증을 요청할 때 저장했던 request 정보를 가져온다.
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = inMemoryOAuth2RequestRepository.deleteOAuth2Request(oAuth2AuthorizationResponse.getState());

        //유저가 로그인 페이지에서 로그인을 취소하거나 오류가 발생했을때 처리
        if (oAuth2AuthorizationResponse.getError() != null) {
            //redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), oAuth2AuthorizationResponse.getError(), response);
            return;
        }

        //사용자의 요청에 맞는 OAuth2 클라이언트 정보를 매핑한다
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider.getProvider());
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider.getProvider());

        //토큰과 유저 정보를 요청
        OAuth2Token oAuth2Token = oAuth2Service.getAccessToken(clientRegistration, oAuth2AuthorizationResponse.getCode(), oAuth2AuthorizationResponse.getState());
        OAuth2UserInfo oAuth2UserInfo = oAuth2Service.getUserInfo(clientRegistration, oAuth2Token.getAccessToken());

        //로그인에 대한 콜백 처리
        if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("login")) {
            UserDetails userDetails = memberQueryService.loginOAuth2User(provider, oAuth2Token, oAuth2UserInfo);
            generateAccessTokenCookie(userDetails, request, response);
        }
        //계정 연동에 대한 콜백 처리
        else if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("link")) {
            //로그인 상태가 아니면
            if (loginUser == null) {
               // redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), "unauthorized", response);
                return;
            }
            try {
                memberQueryService.linkOAuth2Account(loginUser.getUsername(), provider.getProvider(), oAuth2Token, oAuth2UserInfo);
            } catch (Exception e) {
              //  redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), e.getMessage(), response);
                return;
            }
        }

        //콜백 성공
        response.sendRedirect(oAuth2AuthorizationRequest.getRedirectUri());
    }

    private String generateAccessTokenCookie(UserDetails userDetails, HttpServletRequest request, HttpServletResponse response) {
        final int cookieMaxAge = jwtProvider.getAccessTokenExpirationDate().intValue();
        //https 프로토콜인 경우 secure 옵션사용
        boolean secure = request.isSecure();
        String accessToken = jwtProvider.generateAccessToken(userDetails.getUsername());
        //CookieUtils.addCookie(response, "access_token", accessToken, true, secure, cookieMaxAge);

        return accessToken;
    }

    private String generateRefreshTokenCookie(UserDetails userDetails, HttpServletRequest request, HttpServletResponse response) {
        final int cookieMaxAge = jwtProvider.getAccessTokenExpirationDate().intValue();
        //https 프로토콜인 경우 secure 옵션사용
        boolean secure = request.isSecure();
        String accessToken = jwtProvider.generateRefreshToken(userDetails.getUsername());
        //CookieUtils.addCookie(response, "refresh_token", accessToken, true, secure, cookieMaxAge);

        return accessToken;
    }

    private void generateCSRFTokenCookie(HttpServletResponse response) {
        CookieUtils.addCookie(response, StatelessCSRFFilter.CSRF_TOKEN, UUID.randomUUID().toString(), 60 * 60 * 24);
    }

    private void redirectWithErrorMessage(String uri, String message, HttpServletResponse response) throws IOException {
        String redirectUri = UriComponentsBuilder.fromUriString(uri)
                .replaceQueryParam("error", message).encode().build().toUriString();
        response.sendRedirect(redirectUri);
    }

    private String generateState() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }

}
