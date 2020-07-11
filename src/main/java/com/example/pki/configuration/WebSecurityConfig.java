package com.example.pki.configuration;

import com.example.pki.filter.PKIFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author smriti on 06/07/20
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PKIFilter pkiFilter;

    public WebSecurityConfig(PKIFilter pkiFilter) {
        this.pkiFilter = pkiFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .addFilterBefore(pkiFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//                .authorizeRequests()
//                .antMatchers(HttpMethod.POST, "/test/pki").permitAll()
//                .anyRequest().authenticated();
    }
}
