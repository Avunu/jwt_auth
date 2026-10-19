# Copyright (c) 2026, Avunu LLC and contributors
# For license information, please see license.txt

app_description = "JWT Bearer Authentication"
app_email = "mail@avu.nu"
app_include_js = ["app.bundle.js"]
app_license = "mit"
app_name = "jwt_bearer_auth"
app_publisher = "Avunu LLC"
app_title = "JWT Bearer Authentication"

after_request = ["jwt_bearer_auth.auth.handle_redirects"]
auth_hooks = ["jwt_bearer_auth.auth.validate_auth"]
export_python_type_annotations = True
on_logout = ["jwt_bearer_auth.auth.on_logout"]

doc_events = {
	"Contact": {
		"on_update": "jwt_bearer_auth.jwt_auth.hooks.contact.on_update",
	}
}

website_context = {
	"post_login": [
		{"label": "My Account", "url": "/me"},
		{"label": "Log out", "url": "/?cmd=jwt_bearer_auth.auth.web_logout"},
	]
}


# frappe-nix:rename-shim-begin jwt_auth
# jwt_auth's whitelisted methods under their old dotted paths, for callers that still use
# them (cached bundles, webhooks, bookmarks). Written by frappe-rename-app; keep it for
# at least one minor release after the rename.
override_whitelisted_methods = {
	**globals().get("override_whitelisted_methods", {}),
	"jwt_auth.auth.jwt_logout": "jwt_bearer_auth.auth.jwt_logout",
	"jwt_auth.auth.on_logout": "jwt_bearer_auth.auth.on_logout",
	"jwt_auth.auth.web_logout": "jwt_bearer_auth.auth.web_logout",
}
# frappe-nix:rename-shim-end
