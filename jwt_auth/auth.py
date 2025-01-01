import frappe
import json
import jwt
import requests
from urllib.parse import quote
from werkzeug.wrappers import Response
from frappe.website.page_renderers.document_page import DocumentPage
from frappe.website.page_renderers.list_page import ListPage
from frappe.website.page_renderers.not_found_page import NotFoundPage
from frappe.website.page_renderers.print_page import PrintPage
from frappe.website.page_renderers.redirect_page import RedirectPage
from frappe.website.page_renderers.static_page import StaticPage
from frappe.website.page_renderers.template_page import TemplatePage
from frappe.website.page_renderers.web_form import WebFormPage
from frappe.website.path_resolver import PathResolver


class SessionJWTAuth:
    def __init__(self, path=None, http_status_code=None):
        if not hasattr(frappe.local, "jwt_auth"):
            frappe.local.jwt_auth = JWTAuth(path, http_status_code)
        elif path or http_status_code:
            frappe.local.jwt_auth.update(path, http_status_code)

    def __getattr__(self, name):
        # Delegate all attribute access to the cached JWTAuth instance
        return getattr(frappe.local.jwt_auth, name)


class JWTAuth:
    def __init__(self, path=None, http_status_code=None):
        self.path = path
        self.http_status_code = http_status_code
        self.settings = frappe.get_cached_doc("JWT Auth Settings")
        self.claims = None
        self.user_email = None
        self.token = None
        self.redirect_to = (
            None  # Initialize as None, we'll fetch from cache when needed
        )

    def auth(self):
        self.user_email = self.claims.get("email") if self.claims.get("email") else None
        if not self.user_email:
            return
        user_email = self.claims.get("email") if self.claims.get("email") else None
        if user_email:
            frappe.log_error(f"Attempting auth for {user_email}", "JWT Auth Debug")
            # Check if the user exists
            Contact = frappe.qb.DocType("Contact")
            ContactEmail = frappe.qb.DocType("Contact Email")
            user_exists = (
                frappe.qb.from_(Contact)
                .select("user")
                .join(ContactEmail)
                .on(Contact.name == ContactEmail.parent)
                .where(ContactEmail.email_id == user_email)
            ).run(as_dict=True)
            if user_exists:
                frappe.log_error(
                    f"Existing user found for {user_email}", "JWT Auth Debug"
                )
                frappe.local.login_manager.login_as(user_exists[0].get("user"))
            elif self.settings.enable_user_reg:
                frappe.log_error(
                    f"Creating new user for {user_email}", "JWT Auth Debug"
                )
                self.register_user(user_email)
                frappe.local.login_manager.login_as(user_email)
                # Store redirect in session for after_request handling
                if self.redirect_to:
                    frappe.session.data["jwt_auth_redirect"] = self.redirect_to
                    frappe.session.data["jwt_original_location"] = self.path

    def validate_auth(self):
        if self.can_auth():
            self.auth()

    def can_auth(self):
        if self.redirect_to:
            return False
        if frappe.local.session.user and frappe.local.session.user != "Guest":
            return False
        if not self.settings.enabled:
            return False
        self.token = self.get_token(frappe.local.request)
        if not self.token:
            return False
        if self.is_valid_token(self.token):
            return True

    def can_render(self):
        return self.settings.enabled and (
            self.settings.enable_login or self.redirect_to
        )

    def update(self, path, http_status_code):
        self.path = path
        self.http_status_code = http_status_code

    def get_login_url(self, redirect_to=None):
        login_url = self.settings.login_url
        if self.settings.redirect_param:
            redirect_to = redirect_to if redirect_to else self.path
            path = "%2F" + quote(redirect_to, safe="")
            if "?" in login_url:
                login_url += f"&{self.settings.redirect_param}={path}"
            else:
                login_url += f"?{self.settings.redirect_param}={path}"
        return login_url

    def get_logout_url(self):
        logout_url = self.settings.logout_url
        if self.settings.redirect_param:
            logout_url += f"?{self.settings.redirect_param}={frappe.local.request.url}"
        return logout_url

    def get_public_keys(self):
        r = requests.get(self.settings.jwks_url)
        public_keys = []
        jwk_set = r.json()
        for key_dict in jwk_set["keys"]:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
            public_keys.append(public_key)
        return public_keys

    def get_renderer(self):
        path_resolver = PathResolver(self.path, self.http_status_code)
        # remove the current class from the custom renderers
        custom_renderers = [
            renderer
            for renderer in path_resolver.get_custom_page_renderers()
            if renderer.__name__ != self.__class__.__name__
        ]
        renderers = [
            *custom_renderers,
            StaticPage,
            WebFormPage,
            DocumentPage,
            TemplatePage,
            ListPage,
            PrintPage,
        ]
        for renderer in renderers:
            renderer_instance = renderer(self.path, self.http_status_code)
            if renderer_instance.can_render():
                return renderer_instance
        return NotFoundPage(self.path, self.http_status_code)

    def get_token(self, request):
        token = (
            request.cookies.get(self.settings.jwt_header)
            if request.cookies.get(self.settings.jwt_header)
            else (
                request.headers.get(self.settings.jwt_header)
                if request.headers.get(self.settings.jwt_header)
                else None
            )
        )
        return token

    def is_valid_token(self, token):
        keys = self.get_public_keys()
        secret = self.settings.get_password("jwt_private_secret")
        # Loop through the keys
        valid_token = False
        for key in keys:
            try:
                self.claims = jwt.decode(
                    token,
                    key=key,
                    audience=secret,
                    algorithms=["RS256"],
                )
                valid_token = True
                break
            except:
                pass
        return valid_token

    def render_redirect(self, path):
        response = Response()
        response.headers["Location"] = path
        response.status_code = 302
        self.redirect_to = None
        return response

    def render(self):
        # Handle login requests
        if self.settings.enable_login and self.path.startswith("login"):
            params = frappe.local.request.args
            redirect_to = params.get("redirect-to")
            return self.render_redirect(self.get_login_url(redirect_to))

        # Regular page rendering
        try:
            if not self.settings.enable_login:
                return self.get_renderer().render()

            if frappe.session.user == "Guest":
                return self.render_redirect(self.get_login_url(self.path))

            return self.get_renderer().render()
        except frappe.PermissionError:
            return self.render_redirect(self.get_login_url(self.path))

    def register_user(self, user_email):
        """
        Creates a user from existing contact data or creates new user with minimal info.
        """
        contact = frappe.db.get_value(
            "Contact Email", {"email_id": user_email}, "parent"
        )

        if contact:
            # Create user from existing contact
            contact = frappe.get_doc("Contact", contact)
            user = frappe.get_doc(
                {
                    "doctype": "User",
                    "email": user_email,
                    "username": user_email,
                    "first_name": contact.first_name or "[Change Me]",
                    "middle_name": contact.middle_name,
                    "last_name": contact.last_name,
                    "full_name": contact.full_name,
                    "phone": contact.phone,
                    "mobile_no": contact.mobile_no,
                    "gender": contact.gender,
                    "send_welcome_email": 0,
                    "company_name": contact.company_name,
                }
            )
            user.insert(ignore_permissions=True)

            # Link contact to user
            contact.user = user_email
            contact.save(ignore_permissions=True)

            if not contact.first_name:
                self.redirect_to = f"/update-profile/{user_email}/edit"
        else:
            # Create new user with minimal info
            user = frappe.get_doc(
                {
                    "doctype": "User",
                    "email": user_email,
                    "first_name": "[Change Me]",
                    "send_welcome_email": 0,
                }
            )
            user.insert(ignore_permissions=True)

            # Always redirect new users to profile update
            self.redirect_to = f"/update-profile/{user_email}/edit"

        frappe.db.commit()


def handle_redirects(response=None, request=None):
    """After request handler for JWT auth redirects"""
    if not response or not hasattr(frappe, "session"):
        return response

    redirect_to = frappe.session.data.pop("jwt_auth_redirect", None)
    if not redirect_to:
        redirect_to = frappe.session.data.pop("jwt_original_location", None)
    if redirect_to:
        # debug
        frappe.log_error(
            "JWT Auth Debug",
            f"Redirecting to {redirect_to}",
        )
        frappe.log_error(
            "JWT Auth Debug Original Response",
            frappe.session.data.get("jwt_original_location"),
        )
        response.status_code = 302
        response.headers["Location"] = redirect_to

    return


@frappe.whitelist()
def jwt_logout():
    auth = SessionJWTAuth()
    frappe.local.login_manager.logout()
    if auth.settings.enabled:
        return {"redirect_url": auth.get_logout_url()}
    else:
        return {"redirect_url": "/login"}


@frappe.whitelist()
def on_logout():
    auth = SessionJWTAuth()
    auth.redirect_to = auth.get_logout_url()


@frappe.whitelist()
def web_logout():
    auth = SessionJWTAuth()
    frappe.local.login_manager.logout()
    if auth.settings.enabled:
        location = auth.get_logout_url()
    else:
        location = "/login"
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = location


def validate_auth():
    SessionJWTAuth().validate_auth()
