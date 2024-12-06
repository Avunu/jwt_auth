import json
import jwt
import requests
from urllib.parse import quote

import frappe

class BaseProvider:
    """A base class/interface for authentication providers."""
    
    def __init__(self, settings):
        self.settings = settings

    @property
    def enabled(self):
        return self.settings.enabled

    @property
    def enable_login(self):
        return self.settings.enable_login

    @property
    def enable_user_reg(self):
        return self.settings.enable_user_reg

    @property
    def jwt_private_secret(self):
        return self.settings.get_password("jwt_private_secret")

    @property
    def jwt_header(self):
        # For Cloudflare Access tokens, we'll override this in the subclass if needed.
        return "Cf-Access-Token"

    def get_login_url(self, redirect_to=None):
        """Return a constructed login URL for this provider."""
        raise NotImplementedError

    def get_logout_url(self):
        """Return a constructed logout URL for this provider."""
        raise NotImplementedError

    def get_jwks_url(self):
        """Return the JWKS URL for this provider."""
        raise NotImplementedError

    def get_public_keys(self):
        """Retrieve and return public keys for JWT verification."""
        r = requests.get(self.get_jwks_url())
        jwk_set = r.json()
        public_keys = []
        for key_dict in jwk_set["keys"]:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
            public_keys.append(public_key)
        return public_keys


class CloudflareAccessProvider(BaseProvider):
    """Cloudflare Access Provider Implementation.
    Requires 'team_name' and 'aud_tag' fields in JWT Auth Settings.
    Redirect parameters are fixed:
    - Frappe uses `redirect-to` internally.
    - Cloudflare Access expects `redirect_url`.
    """

    @property
    def team_name(self):
        return self.settings.team_name

    @property
    def aud_tag(self):
        return self.settings.aud_tag

    @property
    def jwt_header(self):
        # Cloudflare Access typically passes tokens in `Cf-Access-Token` headers or cookies
        return "Cf-Access-Token"

    def get_jwks_url(self):
        # Cloudflare Access JWKS URL:
        return f"https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/certs"

    def get_login_url(self, redirect_to=None):
        # Cloudflare Access login URL:
        # Example: https://<team_name>.cloudflareaccess.com/cdn-cgi/access/login/<aud_tag>
        login_url = f"https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/login/{self.aud_tag}"

        # If we have a frappe redirect-to parameter, we translate it into cloudflare’s `redirect_url`.
        # `redirect_to` is what frappe uses internally. We know cloudflare expects `redirect_url`.
        if redirect_to:
            path = '%2F' + quote(redirect_to, safe='')
            login_url += f"?redirect_url={path}"

        return login_url

    def get_logout_url(self):
        # Cloudflare Access logout URL:
        # https://<team_name>.cloudflareaccess.com/cdn-cgi/access/logout
        logout_url = f"https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/logout"

        # After logout, redirect user back to the frappe site homepage or a known URL.
        # Cloudflare expects `redirect_url` param.
        site_url = frappe.utils.get_url()
        logout_url += f"?redirect_url={quote(site_url, safe='')}"

        return logout_url
