import json
from typing import Any, Dict, List, Optional, cast
from urllib.parse import quote

import frappe
import jwt
import requests
from frappe.contacts.doctype.contact.contact import Contact
from frappe.utils.redis_wrapper import setup_cache
from jwt.algorithms import RSAAlgorithm
from werkzeug import Request, Response

from jwt_auth.jwt_auth.doctype.jwt_auth_settings.jwt_auth_settings import (
    JWTAuthSettings,
)


class SessionJWTAuth:
    def __init__(
        self, path: Optional[str] = None, http_status_code: Optional[int] = None
    ) -> None:
        if not hasattr(frappe.local, "jwt_auth"):
            frappe.local.jwt_auth = JWTAuth(path, http_status_code)
        elif path or http_status_code:
            frappe.local.jwt_auth.update(path, http_status_code)

    def __getattr__(self, name: str) -> Any:
        return getattr(frappe.local.jwt_auth, name)


class JWTAuth:
    path: Optional[str]
    http_status_code: Optional[int]
    settings: JWTAuthSettings
    claims: Dict[str, Any]
    user_email: Optional[str]
    token: Optional[str]
    redirect_to: Optional[str]

    def __init__(
        self, path: Optional[str] = None, http_status_code: Optional[int] = None
    ) -> None:
        self.path = path
        self.http_status_code = http_status_code
        self.settings = frappe.get_cached_doc("JWT Auth Settings")  # type: ignore
        self.claims = {}
        self.user_email = None
        self.token = None
        self.redirect_to = None

    def auth(self) -> None:
        self.user_email = self.claims.get("email") if self.claims.get("email") else None
        if not self.user_email:
            return
        user_email: Optional[str] = (
            self.claims.get("email") if self.claims.get("email") else None
        )
        if user_email:
            Contact = frappe.qb.DocType("Contact")
            ContactEmail = frappe.qb.DocType("Contact Email")
            user_exists: List[Dict[str, Any]] = (
                frappe.qb.from_(Contact)
                .select("user")
                .join(ContactEmail)
                .on(Contact.name == ContactEmail.parent)
                .where(ContactEmail.email_id == user_email)
            ).run(as_dict=True)
            if user_exists and user_exists[0].get("user", False):
                frappe.local.login_manager.login_as(user_exists[0].get("user"))
            elif self.settings.enable_user_reg:
                self.register_user(user_email)
                frappe.local.login_manager.login_as(user_email)
                if (
                    self.redirect_to
                    and hasattr(frappe, "session")
                    and frappe.session
                    and hasattr(frappe.session, "data")
                    and frappe.session.data is not None
                ):
                    frappe.session.data["jwt_auth_redirect"] = self.redirect_to
                    if frappe.cache is not None:
                        cache = frappe.cache()
                        if cache:
                            cache.set_value(
                                f"jwt_original_location_{user_email}",
                                frappe.local.request.path,
                            )

    def validate_auth(self) -> None:
        if self.can_auth():
            self.auth()

    def can_auth(self) -> bool:
        if self.redirect_to:
            return False
        if (
            hasattr(frappe.local, "session")
            and frappe.local.session
            and frappe.local.session.user
            and frappe.local.session.user != "Guest"
        ):
            return False
        if not self.settings.enabled:
            return False
        if frappe.flags.get("jwt_logout_redirect", False):
            return False
        self.token = self.get_token(frappe.local.request)
        if not self.token:
            return False
        if self.is_valid_token(self.token):
            return True
        return False

    def update(self, path: Optional[str], http_status_code: Optional[int]) -> None:
        self.path = path
        self.http_status_code = http_status_code

    def get_login_url(self, redirect_to: Optional[str] = None) -> str:
        login_url: str = self.settings.login_url
        if self.settings.redirect_param:
            redirect: str = redirect_to if redirect_to else self.path or ""
            path: str = "%2F" + quote(string=redirect, safe="")
            if "?" in login_url:
                login_url += f"&{self.settings.redirect_param}={path}"
            else:
                login_url += f"?{self.settings.redirect_param}={path}"
        return login_url

    def get_logout_url(self) -> str:
        logout_url: str = self.settings.logout_url
        if self.settings.redirect_param:
            logout_url += f"?{self.settings.redirect_param}={frappe.local.request.url}"
        return logout_url

    def get_public_keys(self) -> List[Any]:
        r: requests.Response = requests.get(self.settings.jwks_url)
        public_keys: List[Any] = []
        jwk_set: Dict[str, Any] = r.json()
        for key_dict in jwk_set["keys"]:
            public_key = RSAAlgorithm.from_jwk(json.dumps(key_dict))
            public_keys.append(public_key)
        return public_keys

    def get_token(self, request: Request) -> Optional[str]:
        token: Optional[str] = (
            request.cookies.get(self.settings.jwt_header)
            if request.cookies.get(self.settings.jwt_header)
            else (
                request.headers.get(self.settings.jwt_header)
                if request.headers.get(self.settings.jwt_header)
                else None
            )
        )
        return token

    def is_valid_token(self, token: str) -> bool:
        keys: List[Any] = self.get_public_keys()
        secret: str = str(self.settings.get_password("jwt_private_secret"))
        valid_token: bool = False
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

    def register_user(self, user_email: str) -> None:
        contact: Optional[str] = frappe.db.get_value(
            "Contact Email", {"email_id": user_email}, "parent"  # type: ignore
        )

        if contact:
            contact_doc = Contact("Contact", contact)
            user = frappe.get_doc(
                {
                    "doctype": "User",
                    "email": user_email,
                    "username": user_email,
                    "first_name": contact_doc.first_name or "[Change Me]",
                    "middle_name": contact_doc.middle_name,
                    "last_name": contact_doc.last_name,
                    "full_name": contact_doc.full_name,
                    "phone": contact_doc.phone,
                    "mobile_no": contact_doc.mobile_no,
                    "gender": contact_doc.gender,
                    "send_welcome_email": 0,
                    "company_name": contact_doc.company_name,
                }
            )
            user.insert(ignore_permissions=True)

            contact_doc.user = user_email
            contact_doc.save(ignore_permissions=True)

            if not contact_doc.first_name:
                self.redirect_to = f"/update-profile/{user_email}/edit"
        else:
            user = frappe.get_doc(
                {
                    "doctype": "User",
                    "email": user_email,
                    "first_name": "[Change Me]",
                    "send_welcome_email": 0,
                }
            )
            user.insert(ignore_permissions=True)

            self.redirect_to = f"/update-profile/{user_email}/edit"

        frappe.db.commit()


def handle_redirects(response: Optional[Response], request: Request) -> None:
    if not response or not hasattr(frappe, "session") or not frappe.session:
        return

    if frappe.session.get("user") == "Guest" and frappe.flags.get(
        "jwt_logout_redirect"
    ):
        response.status_code = 302
        response.headers["Location"] = cast(
            str, frappe.flags.pop("jwt_logout_redirect")
        )
        return

    if not hasattr(frappe.session, "data") or frappe.session.data is None:
        return

    redirect_to: Optional[str] = frappe.session.data.pop("jwt_auth_redirect", False)
    if not redirect_to and request.path == "/me":
        cache = None
        if frappe.cache is not None:
            cache = frappe.cache()
        if not cache:
            cache = setup_cache()
        cache_key: str = f"jwt_original_location_{frappe.session.user}"
        redirect_to = cache.get_value(cache_key)
        cache.delete_value(cache_key)
    if redirect_to:
        response.status_code = 302
        response.headers["Location"] = redirect_to

    return


@frappe.whitelist()
def jwt_logout() -> Dict[str, str]:
    auth: SessionJWTAuth = SessionJWTAuth()
    frappe.local.login_manager.logout()
    if auth.settings.enabled:
        return {"redirect_url": auth.get_logout_url()}
    else:
        return {"redirect_url": "/login"}


@frappe.whitelist()
def on_logout() -> None:
    auth: SessionJWTAuth = SessionJWTAuth()
    frappe.flags["jwt_logout_redirect"] = auth.get_logout_url()


@frappe.whitelist()
def web_logout() -> None:
    auth: SessionJWTAuth = SessionJWTAuth()
    frappe.local.login_manager.logout()
    location: str
    if auth.settings.enabled:
        location = auth.get_logout_url()
    else:
        location = "/login"
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = location


def validate_auth() -> None:
    SessionJWTAuth().validate_auth()
