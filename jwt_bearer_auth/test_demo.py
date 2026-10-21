# Copyright (c) 2026, Avunu LLC and contributors
# For license information, please see license.txt

import datetime

import frappe
from frappe.tests.classes import IntegrationTestCase

from jwt_bearer_auth import demo


class TestDemo(IntegrationTestCase):
	"""jwt_bearer_auth.demo.setup, the frappe-demo hook."""

	def tearDown(self) -> None:
		frappe.db.rollback()
		super().tearDown()

	def test_setup_fills_settings_and_registers_users_idempotently(self) -> None:
		ctx = {"today": datetime.date(2026, 1, 15), "seed": 1, "company": None, "erpnext_demo": False}
		demo.setup(ctx)
		demo.setup(ctx)

		settings = frappe.get_single("JWT Auth Settings")
		self.assertEqual(settings.jwt_header, "CF_Authorization")
		self.assertFalse(settings.enable_login)
		self.assertEqual(settings.get_password("jwt_private_secret"), demo.AUDIENCE)
		self.assertFalse(frappe.local.flags.commit)

		self.assertEqual(frappe.db.get_value("User", demo.CONTACT["email"], "first_name"), "Dana")
		self.assertEqual(frappe.db.get_value("User", demo.NEW_EMAIL, "first_name"), "[Change Me]")
		self.assertEqual(frappe.db.count("Contact Email", {"email_id": demo.CONTACT["email"]}), 1)
