package de.panomenal.core.authentication;

public class AppConstants {
    public static final String AUTHENTICATED = "Authenticated";
    public static final String AUTH_HEADER = "Authorization";
    public static final String API_URL = "/api/v1";
    public static final String AUTH_URL = API_URL + "/auth";
    public static final String LOGIN_PATH = "/login";
    public static final String REGISTER_PATH = "/register";
    public static final String VERIFY_PATH = "/verify";
    public static final String VERIFY_TWO_FA_PATH = "/verifyTwoFA";
    public static final String REFRESH_PATH = "/refresh";
    public static final String LOGOUT_PATH = "/logout";
    public static final String TWO_FA_SETUP = "/setupTwoFA";
    public static final String QR_ISSUER = "Panomenal";

    public static final String API_URL_PATTERN = API_URL + "/**";
    public static final String AUTH_URL_PATTERN = AUTH_URL + "/**";
}
