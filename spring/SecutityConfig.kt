package com.book.manager.presentation.config

import com.book.manager.application.service.AuthenticationService
import com.book.manager.application.service.security.BookManagerUserDetailsService
import com.book.manager.domain.enum.RoleType
import com.book.manager.presentation.handler.BookManagerAccessDeniedHandler
import com.book.manager.presentation.handler.BookManagerAuthenticationEntryPoint
import com.book.manager.presentation.handler.BookManagerAuthenticationFailureHandler
import com.book.manager.presentation.handler.BookManagerAuthenticationSuccessHandler
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@EnableWebSecurity
class SecurityConfig(private val authenticationService: AuthenticationService) : WebSecurityConfigurerAdapter() {
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests() //認可設定
            .mvcMatchers("/login").permitAll() //ログインは全て許可
            .mvcMatchers("/admin/**").hasAuthority(RoleType.ADMIN.toString()) //パスがadminのものは権限必
            .anyRequest().authenticated() //それ以外は権限不要
            .and()
            .csrf().disable()
            //認証設定
            .formLogin() //フォームログイン有効化 ユーザー名とパスワード
            .loginProcessingUrl("/login") //ログインAPIのパス設定
            .usernameParameter("email") //ユーザー名のパラメーター設定
            .passwordParameter("pass") //パスワードのパラメーター設定
            //ハンドラー設定
            .successHandler(BookManagerAuthenticationSuccessHandler())//認証成功時のハンドラー
            .failureHandler(BookManagerAuthenticationFailureHandler())//認証失敗時のハンドラー
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(BookManagerAuthenticationEntryPoint())//未認証時のハンドラー
            .accessDeniedHandler(BookManagerAccessDeniedHandler())//認可失敗時のハンドラー
            //CORS設定
            .and()
            .cors()
            .configurationSource(corsConfigurationSource())
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
        //独自で作成したUserDetailsがあれば指定する
        auth.userDetailsService(BookManagerUserDetailsService(authenticationService))
            .passwordEncoder(BCryptPasswordEncoder())
    }

    private fun corsConfigurationSource(): CorsConfigurationSource {
        val corsConfiguration = CorsConfiguration()
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL)//メソッド全て許可
        corsConfiguration.addAllowedHeader((CorsConfiguration.ALL))//ヘッダー全て許可
        corsConfiguration.addAllowedOrigin("http://localhost:8081")//アクセス元ドメイン. 本番、開発環境で設定ファイルなどに記述したほうが良い。
        corsConfiguration.allowCredentials = true

        val corsConfigurationSource = UrlBasedCorsConfigurationSource()
        corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration)

        return corsConfigurationSource
    }
}
