app_description = "JWT Auth"
app_email = "kevin@avu.nu"
app_include_js = ["app.bundle.js"]
app_license = "mit"
app_name = "jwt_auth"
app_publisher = "Avunu LLC"
app_title = "JWT Auth"

after_request = ["jwt_auth.auth.handle_redirects"]
auth_hooks = ["jwt_auth.auth.validate_auth"]
export_python_type_annotations = True
on_logout = ["jwt_auth.auth.on_logout"]

doc_events = {
    "Contact": {
        "on_update": "jwt_auth.jwt_auth.hooks.contact.on_update",
    }
}

website_context = {
    "post_login": [
        {"label": "My Account", "url": "/me"},
        {"label": "Log out", "url": "/?cmd=jwt_auth.auth.web_logout"},
    ]
}
