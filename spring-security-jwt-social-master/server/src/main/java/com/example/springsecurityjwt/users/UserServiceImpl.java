package com.example.springsecurityjwt.users;

import com.example.springsecurityjwt.authentication.oauth2.OAuth2Token;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2Account;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountDTO;
import com.example.springsecurityjwt.authentication.oauth2.account.OAuth2AccountRepository;
import com.example.springsecurityjwt.authentication.oauth2.userInfo.OAuth2UserInfo;
import com.example.springsecurityjwt.security.UserDetailsImpl;
import com.example.springsecurityjwt.validation.SimpleFieldError;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void saveUser(SignUpRequest signUpRequest){
        checkDuplicateEmail(signUpRequest.getEmail());
        User user = User.builder()
                .username(signUpRequest.getEmail())
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .type(UserType.DEFAULT)
                .build();

        userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<OAuth2AccountDTO> getOAuth2Account(String username) {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (!optionalUser.isPresent() || optionalUser.get().getSocial() == null) return Optional.empty();
        return Optional.of(optionalUser.get().getSocial().toDTO());
    }

    @Override
    public void updateProfile(String username, UpdateProfileRequest updateProfileRequest){

        User user = userRepository.findByUsername(username).get();

        //????????? ?????????????????? ??????
        if (!user.getName().equals(updateProfileRequest.getName()))
            user.updateName(updateProfileRequest.getName());

        //???????????? ?????????????????? ??????
        if (!user.getEmail().equals(updateProfileRequest.getEmail())) {
            checkDuplicateEmail(updateProfileRequest.getEmail());
            user.updateEmail(updateProfileRequest.getEmail());
        }
    }


    @Override
    public UserDetails loginOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {

        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId(provider, userInfo.getId());
        User user = null;

        //????????? ????????? ????????????
        if (optOAuth2Account.isPresent()) {
            OAuth2Account oAuth2Account = optOAuth2Account.get();
            user = oAuth2Account.getUser();
            //?????? ????????????
            oAuth2Account.updateToken(oAuth2Token.getToken(), oAuth2Token.getRefreshToken(), oAuth2Token.getExpiredAt());
        }
        //????????? ????????? ???????????? ?????????
        else {
            //?????? ?????? ?????? ??????
            OAuth2Account newAccount = OAuth2Account.builder()
                    .provider(provider)
                    .providerId(userInfo.getId())
                    .token(oAuth2Token.getToken())
                    .refreshToken(oAuth2Token.getRefreshToken())
                    .tokenExpiredAt(oAuth2Token.getExpiredAt()).build();
            oAuth2AccountRepository.save(newAccount);

            //????????? ????????? ?????????
            if (userInfo.getEmail() != null) {
                // ?????? ???????????? ???????????? ????????? ??????????????? ?????? ??? ????????? ?????? ????????? ??????????????? ????????? ?????? ????????????
                user = userRepository.findByEmail(userInfo.getEmail())
                        .orElse(User.builder()
                                .username(provider + "_" + userInfo.getId())
                                .name(userInfo.getName())
                                .email(userInfo.getEmail())
                                .type(UserType.OAUTH)
                                .build());
            }
            //????????? ????????? ?????????
            else {
                user = User.builder()
                        .username(provider + "_" + userInfo.getId())
                        .name(userInfo.getName())
                        .type(UserType.OAUTH)
                        .build();
            }

            //?????? ????????? ???????????? db??? ??????
            if (user.getId() == null)
                userRepository.save(user);

            //???????????? ??????
            user.linkSocial(newAccount);
        }

        return UserDetailsImpl.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .type(user.getType())
                .authorities(user.getAuthorities()).build();
    }

    @Override
    public UserDetails linkOAuth2Account(String username, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {
        User user = checkRegisteredUser(username);

        //?????? ????????? ?????? ??????????????? ????????? ????????? ??????
        Assert.state(oAuth2AccountRepository.existsByProviderAndProviderId(provider, userInfo.getId()) == false, "?????? ????????? ????????? ????????? ?????? ???????????????.");

        //?????? ?????? ?????? ??????
        OAuth2Account oAuth2Account = OAuth2Account.builder()
                .provider(provider)
                .providerId(userInfo.getId())
                .token(oAuth2Token.getToken())
                .refreshToken(oAuth2Token.getRefreshToken())
                .tokenExpiredAt(oAuth2Token.getExpiredAt())
                .build();
        oAuth2AccountRepository.save(oAuth2Account);

        //???????????? ??????
        user.linkSocial(oAuth2Account);

        return UserDetailsImpl.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .type(user.getType())
                .authorities(user.getAuthorities()).build();
    }

    @Override
    public OAuth2AccountDTO unlinkOAuth2Account(String username) {
        User user = checkRegisteredUser(username);

        //???????????? ??????
        OAuth2Account oAuth2Account = user.getSocial();
        OAuth2AccountDTO oAuth2AccountDTO = oAuth2Account.toDTO();
        user.unlinkSocial();
        oAuth2AccountRepository.delete(oAuth2Account);

        return oAuth2AccountDTO;
    }

    @Override
    public Optional<OAuth2AccountDTO> withdrawUser(String username) {
        OAuth2AccountDTO oAuth2AccountDTO = null;
        User user = checkRegisteredUser(username);
        //????????? ?????? ????????? ????????? ?????? ????????? ???????????? ?????? ??????
        if(user.getSocial() != null)
            oAuth2AccountDTO = user.getSocial().toDTO();
        userRepository.delete(user);
        return Optional.ofNullable(oAuth2AccountDTO);
    }

    private void checkDuplicateEmail(String email) {
        if(userRepository.existsByEmail(email))
            throw new DuplicateUserException("???????????? ????????? ?????????.", new SimpleFieldError("email", "???????????? ????????? ?????????."));
    }

    private User checkRegisteredUser(String username) {
        Optional<User> optUser = userRepository.findByUsername(username);
        Assert.state(optUser.isPresent(), "???????????? ?????? ???????????????.");
        return optUser.get();
    }
}
