import frappe
from frappe.core.doctype.user.user import User


def on_update(doc, method):
	if "[Change Me]" in doc.name and doc.get("full_name"):
		frappe.enqueue(
			"frappe.model.rename_doc.rename_doc",
			doctype=doc.get("doctype"),
			old=doc.get("name"),
			new=doc.get("full_name"),
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
