<!-- Copyright (c) 2026, Avunu LLC and contributors
For license information, please see license.txt-->

# JWT Bearer Authentication for Frappe

**JWT Bearer Authentication** is a Frappe App that enables authentication via JWT tokens, integrating seamlessly with identity providers like Cloudflare Access. Instead of relying on native Frappe logins, this app authenticates incoming requests against a configured identity provider's JWT token, automatically logging in or registering users as needed.

## Features

- **Any JWKS-based identity provider:**  
  Tokens are RS256 JWTs verified against the provider's JWKS endpoint and checked for your application's audience. Cloudflare Access is the provider this app is used with.

- **Automatic Login and Registration:**  
  If the incoming JWT is valid and the user exists, they are immediately logged in. If the user does not exist but user registration is enabled, a new user will be created from existing `Contact` information or a placeholder user will be created, prompting profile updates.

- **Customizable Login and Logout URLs:**  
  The login and logout URLs and the redirect parameter are settings, so the app works with any single sign-on (SSO) front door that issues JWTs.

- **Hooks:**
  - `auth_hooks = ["jwt_bearer_auth.auth.validate_auth"]` validates the JWT on every request.
  - `on_logout = ["jwt_bearer_auth.auth.on_logout"]` sends the user to the provider's logout URL.
  - `after_request = ["jwt_bearer_auth.auth.handle_redirects"]` applies the login, logout and post-registration redirects.
  - The desk's **Log out** goes through `jwt_bearer_auth.auth.jwt_logout`, so the provider's session ends too.

## Prerequisites

- Frappe Framework v16.
- An existing Identity Provider (IdP) that issues JWT tokens, such as Cloudflare Access.

## Installation

Navigate to your bench directory and install the app:

```bash
bench get-app https://github.com/Avunu/jwt_bearer_auth.git
bench --site your-site-name install-app jwt_bearer_auth
```

## Configuration

**JWT Auth Settings** (open it from the desk search):

- **Enable JWT User Auth:** turn JWT-based authentication on.
- **Enable New User Registration:** create a user when a valid token names an email with no user yet.
- **Override Frappe Login:** send unauthenticated users to the provider's login URL.
- **JWT Cookie/Header:** the cookie or header that carries the token (for Cloudflare Access, `CF_Authorization` or `Cf-Access-Jwt-Assertion`).
- **JWKS URL:** the provider's public keys (for Cloudflare Access, `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`).
- **JWT Private Secret:** the audience the token must be issued for (for Cloudflare Access, the application's AUD tag). Without it, every token is rejected.
- **Login URL**, **Logout URL** and **Redirect Param:** where to send users to log in and out, and the query parameter that carries the page to return to.

## Usage

- **Login:**  
  If `Enable Login` is checked and a user hits a page while unauthenticated, they will be redirected to the provider’s login URL.

- **Logout:**  
  Logging out from the Frappe interface or calling `/?cmd=jwt_bearer_auth.auth.web_logout` will revoke the session and redirect the user to the provider’s logout URL.

- **Automatic Redirection:**  
  Unauthenticated users are redirected to the login URL. If registration is enabled and the user does not exist, a new user is created and optionally redirected to a profile update page.

## Troubleshooting

- **Invalid Token Errors:**  
  Check that **JWT Private Secret** (the audience) is set and correct, and that the **JWKS URL** is reachable from the server.

- **Users Not Created:**  
  Make sure `Enable User Reg` is checked and that the user’s email is present in the JWT claims. If user registration logic relies on the `Contact` doctype, ensure `Contact` records exist, or fallback logic creates a placeholder user.

- **Redirect Loops:**  
  If you experience redirect loops, verify that you are receiving a valid token from your IdP. Confirm that the token arrives in the header or cookie named in **JWT Cookie/Header**.

## License

MIT License. See [license.txt](./license.txt) for more details.
