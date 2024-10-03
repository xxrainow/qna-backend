package com.example.qna_backend.user.service;

import com.example.qna_backend.user.domain.User;
import com.example.qna_backend.user.dto.LoginRequest;
import com.example.qna_backend.user.dto.SignupRequest;
import com.example.qna_backend.user.dto.UserInfo;
import com.example.qna_backend.user.exception.AlreadyExistsEmailException;
import com.example.qna_backend.user.exception.AlreadyExistsUsernameException;
import com.example.qna_backend.user.exception.PasswordNotMatchException;
import com.example.qna_backend.user.exception.UserNotFound;
import com.example.qna_backend.user.repository.UserRepository;
import com.example.qna_backend.utils.PasswordEncoder;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void signup(SignupRequest signupRequest) {
        Optional<User> userOptional = userRepository.findByEmail(signupRequest.getEmail());
        if (userOptional.isPresent()) {
            if (userOptional.get().getUsername().equals(signupRequest.getUsername())) {
                throw new AlreadyExistsUsernameException();
            }
            throw new AlreadyExistsEmailException();
        }
        if (!Objects.equals(signupRequest.getPassword1(), signupRequest.getPassword2())) {
            throw new PasswordNotMatchException();
        }

        String encryptedPassword = getEncryptedPassword(signupRequest.getEmail(),signupRequest.getPassword1());

        User user = User.builder()
                .email(signupRequest.getEmail())
                .password(encryptedPassword)
                .username(signupRequest.getUsername())
                .build();

        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public UserInfo login(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(UserNotFound::new);

        String encryptedPassword = getEncryptedPassword(loginRequest.getEmail(), loginRequest.getPassword());

        if (!Objects.equals(user.getPassword(), encryptedPassword)) {
            throw new PasswordNotMatchException();
        }

        return UserInfo.builder()
                .id(user.getId())
                .email(user.getEmail())
                .password(user.getPassword())
                .username(user.getUsername())
                .build();
    }

    private String getEncryptedPassword(String email, String password) {
        return passwordEncoder.encode(email, password);
    }
}