// Copyright (c) 2026, Avunu LLC and contributors
// For license information, please see license.txt

/** What `jwt_auth.auth.jwt_logout` returns: where to send the browser once the Frappe session is gone. */
interface JwtLogoutMessage {
	redirect_url: string;
}

type DeskApplication = InstanceType<typeof frappe.Application>;

/**
 * Desk logout through the identity provider: end the Frappe session on the server, then follow the
 * provider's logout URL (or Frappe's login page when JWT auth is off), so the provider's session ends too
 * and the next request doesn't log the user straight back in.
 */
function jwtLogout(this: DeskApplication): void {
	this.logged_out = true;
	frappe.call<JwtLogoutMessage>({
		method: "jwt_auth.auth.jwt_logout",
		callback: (r) => {
			if (r.exc) {
				return;
			}
			const redirectUrl = r.message?.redirect_url;
			if (redirectUrl) {
				window.location.href = redirectUrl;
			} else {
				this.redirect_to_login();
			}
		},
	});
}

// Desk bundles from app_include_js run after frappe's desk bundle defines frappe.Application and before
// frappe.start_app() creates frappe.app on DOM ready, so replacing the prototype method covers the one
// instance without polling for it.
frappe.Application.prototype.logout = jwtLogout;
