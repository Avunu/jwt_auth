# Copyright (c) 2026, Avunu LLC and contributors
# For license information, please see license.txt

from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import frappe
from frappe.tests.classes import IntegrationTestCase
from frappe.utils import random_string

if TYPE_CHECKING:
	from frappe.contacts.doctype.contact.contact import Contact


class TestContactOnUpdate(IntegrationTestCase):
	"""jwt_bearer_auth.jwt_auth.hooks.contact.on_update (doc_events: Contact on_update)."""

	def tearDown(self) -> None:
		frappe.db.rollback()
		super().tearDown()

	def test_placeholder_contact_is_renamed_once_named(self) -> None:
		contact = cast("Contact", frappe.get_doc({"doctype": "Contact", "first_name": "[Change Me]"}))
		contact.insert(ignore_permissions=True)
		self.assertIn("[Change Me]", str(contact.name))
		last_name = f"Roe{random_string(6)}"

		with patch("jwt_bearer_auth.jwt_auth.hooks.contact.frappe.enqueue") as enqueue:
			contact.first_name = "Jane"
			contact.last_name = last_name
			contact.save(ignore_permissions=True)

		enqueue.assert_called_once()
		self.assertEqual(enqueue.call_args.args[0], "frappe.model.rename_doc.rename_doc")
		self.assertEqual(enqueue.call_args.kwargs["old"], contact.name)
		self.assertEqual(enqueue.call_args.kwargs["new"], f"Jane {last_name}")

	def test_placeholder_rename_avoids_an_existing_name(self) -> None:
		last_name = f"Roe{random_string(6)}"
		frappe.get_doc({"doctype": "Contact", "first_name": "Jane", "last_name": last_name}).insert(
			ignore_permissions=True
		)
		contact = cast("Contact", frappe.get_doc({"doctype": "Contact", "first_name": "[Change Me]"}))
		contact.insert(ignore_permissions=True)

		with patch("jwt_bearer_auth.jwt_auth.hooks.contact.frappe.enqueue") as enqueue:
			contact.first_name = "Jane"
			contact.last_name = last_name
			contact.save(ignore_permissions=True)

		self.assertNotEqual(enqueue.call_args.kwargs["new"], f"Jane {last_name}")
		self.assertTrue(enqueue.call_args.kwargs["new"].startswith(f"Jane {last_name}"))

	def test_named_contact_is_not_renamed(self) -> None:
		contact = cast(
			"Contact", frappe.get_doc({"doctype": "Contact", "first_name": f"Named{random_string(6)}"})
		)
		contact.insert(ignore_permissions=True)

		with patch("jwt_bearer_auth.jwt_auth.hooks.contact.frappe.enqueue") as enqueue:
			contact.last_name = "Changed"
			contact.save(ignore_permissions=True)

		enqueue.assert_not_called()

	def test_linked_user_gets_the_changed_fields(self) -> None:
		email = f"contact{random_string(8).lower()}@example.com"
		frappe.get_doc(
			{"doctype": "User", "email": email, "first_name": "Old", "user_type": "Website User"}
		).insert(ignore_permissions=True)
		contact = cast("Contact", frappe.get_doc({"doctype": "Contact", "first_name": "Old", "user": email}))
		contact.insert(ignore_permissions=True)

		contact.first_name = "New"
		contact.save(ignore_permissions=True)

		self.assertEqual(frappe.db.get_value("User", email, "first_name"), "New")
