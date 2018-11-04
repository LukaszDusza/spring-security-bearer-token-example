package com.auth0.security;

public class SecurityConstants {
    public static final String SECRET = "SecretKeyToGenJWTs";
    public static final long EXPIRATION_TIME = 86_400_000; // 1 day
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/users/sign-up";
    public static final String HOME = "/";
    public static final String H2 = "/h2-console/**";
    public static final String TASKS = "/tasks";
    public static final String SWAGGER = "/swagger-ui.html/**";
}