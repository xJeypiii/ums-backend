package dev.jpjbriones.ums.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/all")
    public ResponseEntity<?> allAccess() {
        return  ResponseEntity.ok("Public Content.");
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<?> userAccess() {
        return ResponseEntity.ok("User Content.");
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<?> moderatorAccess() {
        return ResponseEntity.ok("Moderator Board.");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminAccess() {
        return ResponseEntity.ok("Admin Board.");
    }
}
