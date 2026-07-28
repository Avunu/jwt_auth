from __future__ import annotations

from typing import TYPE_CHECKING

import frappe
from frappe.core.doctype.user.user import User
from frappe.model.naming import append_number_if_name_exists
from frappe.utils import cstr

if TYPE_CHECKING:
	from frappe.contacts.doctype.contact.contact import Contact


def on_update(doc: Contact, _method):
	if "[Change Me]" in str(doc.name) or doc.full_name == "[Change Me]":
		full_name = doc._get_full_name()
		if full_name and full_name != "[Change Me]":
			# Calculate new name using the same logic as Contact.autoname()
			new_name = full_name

			if frappe.db.exists("Contact", new_name):
				new_name = append_number_if_name_exists("Contact", new_name)

			if full_name != doc.full_name:
				frappe.db.set_value("Contact", str(doc.name), "full_name", full_name)

			# Only rename if the new name is different
			if new_name != doc.name:
				frappe.enqueue(
					"frappe.model.rename_doc.rename_doc",
					doctype=doc.get("doctype"),
					old=doc.get("name"),
					new=new_name,
					force=False,
					show_alert=True,
					ignore_permissions=True,
				)

	if doc.get("user", False):
		# Update user's fields from contact
		user_fields = {
			"first_name": doc.get("first_name", None),
			"middle_name": doc.get("middle_name", None),
			"last_name": doc.get("last_name", None),
			"full_name": doc.get("full_name", None),
			"phone": doc.get("phone", None),
			"mobile_no": doc.get("mobile_no", None),
			"gender": doc.get("gender", None),
		}

		# Only update fields that have changed
		update_fields = {
			field: value
			for field, value in user_fields.items()
			if doc.has_value_changed(field) and value is not None
		}

		if update_fields:
			user = User("User", doc.get("user"))
			user.update(update_fields)
			user.save(ignore_permissions=True)
