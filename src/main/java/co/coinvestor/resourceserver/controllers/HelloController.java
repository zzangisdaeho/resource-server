package co.coinvestor.resourceserver.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
public class HelloController {

    @GetMapping("/hello")
//    @PreAuthorize("hasAuthority('ADMIN')")
    public String hello(Authentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }

    @GetMapping("/hello2")
    @PreAuthorize("authentication.principal.claims['authorities'].contains('ADMIN')")
    public String hello2(Authentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }

    @GetMapping("/hello3")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String hello3(Authentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }

    @GetMapping("/hello4")
    @PreAuthorize("principal.claims['authorities'].contains('ADMIN')")
    public String hello4(Authentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }

    @GetMapping("/hello5")
    @PreAuthorize("principal.claims['scope'].contains('SPOT')")
    public String hello5(Authentication au) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("oAuth2User = " + au);
        return "Hello!";
    }
}
