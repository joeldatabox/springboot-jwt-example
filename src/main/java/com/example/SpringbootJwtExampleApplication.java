package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class SpringbootJwtExampleApplication {

    @RestController
    protected static class HomeController {
        @RequestMapping(value = "/", method = RequestMethod.GET, produces = "application/json")
        public Map<String, String> home() {
            HashMap<String, String> returnValue = new HashMap<>();
            returnValue.put("home", "home");
            return returnValue;
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringbootJwtExampleApplication.class, args);
    }

    protected static class ApplicationSecurity extends WebSecurityConfigurerAdapter {
        @Value("${JWT_SECRET:defaultSecret}")
        protected String secret;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .authorizeRequests()
                    .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and().authorizeRequests()
                    .anyRequest().authenticated().and()
                    .httpBasic().and()
                    .addFilterBefore(new SpringSecurityJWTAuthenticationFilter(super.authenticationManagerBean()), BasicAuthenticationFilter.class)
                    .addFilterAfter(new SpringSecurityAddJWTTokenFilter(jwtAuthenticationProvider()), BasicAuthenticationFilter.class);

        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            /*auth
                    .authenticationProvider(jwtAuthenticationProvider())
                    .inMemoryAuthentication()
                    .withUser("user")
                    .password("user1")
                    .roles("USER");*/
            auth.authenticationProvider(jwtAuthenticationProvider());
        }

        /**
         * Cria um novo provider JWT
         */
        @Bean
        public JWTAuthenticationProvider jwtAuthenticationProvider() {
            return new JWTAuthenticationProvider(secret);
        }
    }
}
