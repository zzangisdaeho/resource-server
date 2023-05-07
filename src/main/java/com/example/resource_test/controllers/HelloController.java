package com.example.resource_test.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collection;

@RestController
public class HelloController {

    @GetMapping("/hello1")
//    @PreAuthorize("hasAuthority('ADMIN')")
    public String hello1(Authentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }

    @GetMapping("/hello2")
    @PreAuthorize("principal.attributes['scope'].contains('SPOT')")
    public String hello2(BearerTokenAuthentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }

    @GetMapping("/hello3")
    @PreAuthorize("principal.attributes['scope'].contains('SPOT')")
    public String hello3(Authentication au, BearerTokenAuthentication bu, Principal pr) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + pr);
        return "Hello!";
    }

    @GetMapping("/hello4")
    @PreAuthorize("principal.attributes['authorities'].contains('ADMIN')")
    public String hello4(Authentication au, BearerTokenAuthentication bu, Principal pr) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + pr);
        return "Hello!";
    }

    @GetMapping("/hello5")
    @PreAuthorize("principal.attributes['authorities'].contains('MASTER')")
    public String hello5(Authentication au, BearerTokenAuthentication bu, Principal pr) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + pr);
        return "Hello!";
    }

    @GetMapping("/hello6")
    @PreAuthorize("principal.attributes['scope'].contains('WTF')")
    public String hello6(Authentication au, BearerTokenAuthentication bu, Principal pr) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + pr);
        return "Hello!";
    }
}
