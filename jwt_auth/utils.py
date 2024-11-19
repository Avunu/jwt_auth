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


def before_request():
    """
    JWT Auth Middleware
    1.  is user authenticated? yes, return; no, continue
    2.  is jwt enabled? no, return; yes, continue
    3.  is cookie/header set? no, return; yes, continue
    4.  is token valid? no, return; yes, continue
    5.  does user exist? yes, post_login; no, continue
    6.  is user-reg enabled? yes, register user, no, return
    """

    request = frappe.local.request

    # is user authenticated?
    if frappe.local.session.user and frappe.local.session.user != "Guest":
        return

    settings = frappe.get_doc("JWT Auth Settings")

    # is jwt enabled? is cookie/header set?
    if not settings.enable_jwt_user_auth or not settings.jwt_header: # move this validation to the JWT Auth Settings validation hook
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
        frappe.local.login_manager.user = user_email
        frappe.local.login_manager.post_login()
    elif user_email:
        if settings.allow_new_user_registration:
            register_user(user_email)
    else:
        return
    
    return 


def after_request(response, request):
    # Log request details
    try:
        request_headers = dict(request.headers)
        request_data = request.get_data(as_text=True)  # Raw data in the request body
        request_details = {
            "method": request.method,
            "path": request.path,
            "headers": request_headers,
            "body": request_data,
        }
        frappe.log_error(
            title="After Request - Request Details",
            message=frappe.as_json(request_details)  # Convert to JSON for better readability
        )
    except Exception as e:
        frappe.log_error(title="Error Logging Request", message=str(e))

    # Log response details
    try:
        response_headers = dict(response.headers)
        response_data = response.get_data(as_text=True)  # Raw response body
        response_details = {
            "status_code": response.status_code,
            "headers": response_headers,
            "body": response_data,
            "redirect_to": response.location,
        }
        frappe.log_error(
            title="After Request - Response Details",
            message=frappe.as_json(response_details)  # Convert to JSON for better readability
        )
    except Exception as e:
        frappe.log_error(title="Error Logging Response", message=str(e))

    return response


def register_user(user_email):
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
    # frappe.local.login_manager.user = user_email
    # frappe.local.login_manager.post_login()
    frappe.local.login_manager.login_as(user_email)
    registration_url = f"/update-profile/{user_email}/edit"
    # frappe.local.response["redirect_to"] = registration_url

    # frappe.set_route(registration_url)
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = registration_url

    frappe.local.request["type"] = "redirect"
    frappe.local.request["location"] = registration_url

    response = frappe.local.response
    request = frappe.local.request
    frappe.log_error(
        f"Redirecting to {registration_url}",
        response,
    )
    frappe.log_error(
        f"Redirecting to {registration_url}",
        request,
    )

    # try:
    #     frappe.redirect(registration_url)
    # except Exception as e:
    #     frappe.log_error(
    #         f"Could not redirect to {registration_url}",
    #         e,
    #     )
    # frappe.local.response["type"] = "redirect"
    # frappe.local.response["location"] = registration_url
    # raise frappe.Redirect
