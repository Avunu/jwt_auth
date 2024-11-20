import frappe
import json
import jwt
import requests


def _get_public_keys(certs_url):
    """
    Returns:
        List of RSA public keys usable by PyJWT.
    """
    r = requests.get(certs_url)
    public_keys = []
    jwk_set = r.json()
    for key_dict in jwk_set["keys"]:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
        public_keys.append(public_key)
    return public_keys


def after_request(response, request):
    """
    JWT Auth Middleware
    1.  is user authenticated? yes, return; no, continue
    2.  is jwt enabled? no, return; yes, continue
    3.  is cookie/header set? no, return; yes, continue
    4.  is token valid? no, return; yes, continue
    5.  does user exist? yes, post_login; no, continue
    6.  is user-reg enabled? yes, register user, no, return
    """

    # is user authenticated?
    if frappe.local.session.user and frappe.local.session.user != "Guest":
        return

    settings = frappe.get_doc("JWT Auth Settings")

    # is jwt enabled?
    if not settings.enable_jwt_user_auth:
        return

    # is token valid?
    token = (
        request.cookies.get(settings.jwt_header)
        if request.cookies.get(settings.jwt_header)
        else (
            request.headers.get(settings.jwt_header)
            if request.headers.get(settings.jwt_header)
            else None
        )
    )
    if not token:
        return

    try:
        keys = _get_public_keys(settings.jwks_url)
    except:
        return

    # Loop through the keys
    valid_token = False
    for key in keys:
        try:
            claims = jwt.decode(
                token,
                key=key,
                audience=settings.get_password("jwt_private_secret"),
                algorithms=["RS256"],
            )
            valid_token = True
            break
        except:
            pass
    if not valid_token:
        return

    user_email = claims.get("email") if claims.get("email") else None

    # does user exist?
    if user_email and frappe.db.exists("User", {"email": user_email}):
        frappe.local.login_manager.login_as(user_email)
    elif user_email:
        if settings.allow_new_user_registration:
            register_user(user_email, response)
    else:
        return

    return


def register_user(user_email, response):
    """
    Redirects to the registration page with a pre-filled email parameter.
    """

    # make a new user, required fields being email and first name. Use a placeholder for first name.
    frappe.get_doc(
        {
            "doctype": "User",
            "email": user_email,
            "first_name": "[Change Me]",
            "send_welcome_email": 0,
        }
    ).insert(ignore_permissions=True)
    frappe.db.commit()

    frappe.local.login_manager.login_as(user_email)

    response.headers["Location"] = f"/update-profile/{user_email}/edit"
    response.status_code = 302
