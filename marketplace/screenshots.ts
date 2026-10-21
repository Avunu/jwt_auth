// Copyright (c) 2026, Avunu LLC and contributors
// For license information, please see license.txt

import type { ShotSpec } from "./shots.d.ts";

export default {
	demo: { date: "2026-01-15", seed: 1 },
	shots: [
		{
			name: "settings",
			route: "/app/jwt-auth-settings",
			alt: "JWT Auth Settings filled in for Cloudflare Access: token cookie, JWKS URL, audience, and login and logout URLs",
			waitFor: ".form-layout",
			readme: "hero",
			featured: true,
		},
		{
			name: "registered-users",
			route: "/app/user?user_type=Website%20User&name=%5B%22!%3D%22%2C%22Guest%22%5D",
			alt: "The user list with two website users created from a token: one filled in from a Contact, one still to complete their profile",
			waitFor: ".frappe-list .list-row",
			mask: [".frappe-timestamp"],
			readme: "feature",
		},
	],
} satisfies ShotSpec;
