# JWT Bearer Authentication for Frappe

**JWT Bearer Authentication** is a Frappe App that enables authentication via JWT tokens, integrating seamlessly with identity providers like Cloudflare Access. Instead of relying on native Frappe logins, this app authenticates incoming requests against a configured identity provider's JWT token, automatically logging in or registering users as needed.

## Features

- **Any JWKS-based identity provider:**  
  Tokens are RS256 JWTs verified against the provider's JWKS endpoint and checked for your application's audience. Cloudflare Access is the provider this app is used with.

- **Automatic Login and Registration:**  
  If the incoming JWT is valid and the user exists, they are immediately logged in. If the user does not exist but user registration is enabled, a new user will be created from existing `Contact` information or a placeholder user will be created, prompting profile updates.

- **Customizable Login and Logout URLs:**  
  The logout URL and the redirect parameter are settings, so the app works with any single sign-on (SSO) front door that issues JWTs. The login URL is a setting too, but it is used only by **Override Frappe Login**, which currently has no effect.

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
bench get-app https://github.com/Avunu/jwt_bearer_auth
bench --site your-site-name install-app jwt_bearer_auth
```

## Configuration

**JWT Auth Settings** (open it from the desk search):

- **Enable JWT User Auth:** turn JWT-based authentication on.
- **Enable New User Registration:** create a user when a valid token names an email with no user yet.
- **Override Frappe Login:** meant to redirect requests for Frappe's `/login` page to the **Login URL**. It currently has no effect; see [Limitations](../README.md#limitations).
- **JWT Cookie/Header:** the cookie or header that carries the token (for Cloudflare Access, `CF_Authorization` or `Cf-Access-Jwt-Assertion`).
- **JWKS URL:** the provider's public keys (for Cloudflare Access, `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`).
- **JWT Private Secret:** the audience the token must be issued for (for Cloudflare Access, the application's AUD tag). Without it, every token is rejected.
- **Logout URL:** where users are sent after logging out.
- **Login URL:** used only by **Override Frappe Login**, so it currently has no effect.
- **Redirect Param:** the query parameter that carries the page to return to, added to the logout URL (and to the login URL once the override works).

## Usage

- **Login:**  
  Users who reach the site with a valid token from the identity provider are logged in automatically. **Override Frappe Login** is meant to redirect requests for Frappe's `/login` page to the **Login URL**, but it currently has no effect (see [Limitations](../README.md#limitations)); visitors who reach `/login` see Frappe's login page.

- **Logout:**  
  Logging out from the Frappe interface or calling `/?cmd=jwt_bearer_auth.auth.web_logout` will revoke the session and redirect the user to the provider’s logout URL.

- **Automatic Redirection:**  
  If registration is enabled and the user does not exist, a new user is created and optionally redirected to a profile update page.

## Troubleshooting

- **Invalid Token Errors:**  
  Check that **JWT Private Secret** (the audience) is set and correct, and that the **JWKS URL** is reachable from the server.

- **Users Not Created:**  
  Make sure **Enable New User Registration** is checked and that the user’s email is present in the JWT claims. If user registration logic relies on the `Contact` doctype, ensure `Contact` records exist, or fallback logic creates a placeholder user.

- **Redirect Loops:**  
  If you experience redirect loops, verify that you are receiving a valid token from your IdP. Confirm that the token arrives in the header or cookie named in **JWT Cookie/Header**.

## License

MIT License. See [license.txt](https://github.com/Avunu/jwt_bearer_auth/blob/develop/license.txt) for more details.
