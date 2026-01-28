package com.example.demo.service;

import java.util.Collections;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
public class UserService implements UserDetailsService {
    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public UserService(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    public User register(String username, String rawPassword) {
        if (repo.existsByUsername(username)) throw new RuntimeException("Usuario ya existe");
        User u = new User();
        u.setUsername(username);
        u.setPassword(encoder.encode(rawPassword));
        return repo.save(u);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = repo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("No encontrado"));
        return new org.springframework.security.core.userdetails.User(
                u.getUsername(), u.getPassword(), Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }
}
