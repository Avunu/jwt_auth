# Copyright (c) 2026, Avunu LLC and contributors
# For license information, please see license.txt

"""Demo data for frappe-demo: idempotent, no network, and no commit (frappe-demo commits once)."""

from typing import Any

import frappe

from jwt_bearer_auth.auth import JWTAuth

# Cloudflare Access values for a fictitious team and site; nothing here is ever fetched.
SETTINGS: dict[str, Any] = {
	"enabled": 1,
	"enable_user_reg": 1,
	# Off, so the demo site's own login page stays reachable for frappe-shots.
	"enable_login": 0,
	"jwt_header": "CF_Authorization",
	"jwks_url": "https://example-team.cloudflareaccess.com/cdn-cgi/access/certs",
	"login_url": "https://example-team.cloudflareaccess.com/cdn-cgi/access/login/erp.example.com",
	"logout_url": "https://erp.example.com/cdn-cgi/access/logout",
	"redirect_param": "redirect_url",
}
AUDIENCE = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2"

# Two users registered from a token: one matching an existing Contact, one with no Contact.
CONTACT = {"first_name": "Dana", "last_name": "Reyes", "email": "dana.reyes@example.com"}
NEW_EMAIL = "sam.okafor@example.com"


def setup(_ctx: dict[str, Any]) -> None:
	"""Fill in the settings and register two users; nothing here depends on the demo date."""
	settings = frappe.get_single("JWT Auth Settings")
	settings.update(SETTINGS)
	settings.jwt_private_secret = AUDIENCE
	settings.save(ignore_permissions=True)

	if not frappe.db.exists("Contact Email", {"email_id": CONTACT["email"]}):
		frappe.get_doc(
			{
				"doctype": "Contact",
				"first_name": CONTACT["first_name"],
				"last_name": CONTACT["last_name"],
				"email_ids": [{"email_id": CONTACT["email"], "is_primary": 1}],
			}
		).insert(ignore_permissions=True)

	# The app's own registration path, as a valid token for these emails would run it.
	auth = JWTAuth()
	for email in (CONTACT["email"], NEW_EMAIL):
		auth.register_user(email)
	# register_user asks the web request to commit; frappe-demo commits at the end instead.
	frappe.local.flags.commit = False
