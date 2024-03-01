package maxi.maran.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public InMemoryUserDetailsManager user(){
        return new InMemoryUserDetailsManager(
                User.withUsername("maxi")
                        .password("{noop}Atlas")
                        .authorities("read")
                        .build()
        );
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                //Disable csrf (Cross Site Request Forgery Protection)
                .csrf(csrf -> csrf.disable())
                //The user should be authenticated for any request in the application
                .authorizeRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                //Spring Security will never create an HttpSession, and it will never use it to obtain the Security Context.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //Spring Security's HTTP Basic Authentication support is enabled by default. However, as soon as any servlet-based configuration is provided, HTTP Basic must be explicitly provided.
                .httpBasic(withDefaults())
                .build();
    }
}
