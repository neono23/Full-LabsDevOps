package unitbv.devops.authenticationapi.controller;

import unitbv.devops.authenticationapi.dto.auth.LoginRequest;
import unitbv.devops.authenticationapi.dto.auth.LoginResponse;
import unitbv.devops.authenticationapi.dto.auth.RegisterRequest;
import unitbv.devops.authenticationapi.dto.auth.TokenRefreshRequest;
import unitbv.devops.authenticationapi.user.entity.Role;
import unitbv.devops.authenticationapi.user.entity.Token;
import unitbv.devops.authenticationapi.user.entity.User;
import unitbv.devops.authenticationapi.user.repository.TokenRepository;
import unitbv.devops.authenticationapi.user.repository.UserRepository;
import unitbv.devops.authenticationapi.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        if (userRepository.existsByEmail(request.email())) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRoles(Set.of(Role.USER));
        user.setCreatedAt(Instant.now());
        user.setEnabled(true);

        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        User user = userRepository.findByUsername(request.usernameOrEmail())
                .or(() -> userRepository.findByEmail(request.usernameOrEmail()))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // Generate tokens
        List<String> roles = user.getRoles().stream().map(Enum::name).collect(Collectors.toList());
        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), roles);
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        // Save tokens to database
        Token token = new Token(accessToken, refreshToken, user);
        tokenRepository.save(token);

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }

    @PostMapping("/token")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
        // Find the token pair
        Token existingToken = tokenRepository
                .findByAccessTokenAndRefreshToken(request.getAccessToken(), request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Invalid token pair"));

        // Mark as blacklisted
        existingToken.setBlacklisted(true);
        tokenRepository.save(existingToken);

        // Validate refresh token and get user
        String username = jwtUtil.extractUsername(request.getRefreshToken());
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Generate new token pair
        List<String> roles = user.getRoles().stream().map(Enum::name).collect(Collectors.toList());
        String newAccessToken = jwtUtil.generateAccessToken(user.getUsername(), roles);
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        // Save new tokens
        Token newToken = new Token(newAccessToken, newRefreshToken, user);
        tokenRepository.save(newToken);

        return ResponseEntity.ok(new LoginResponse(newAccessToken, newRefreshToken));
    }
}