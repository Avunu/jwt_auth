import frappe


def on_update(doc, method):

    if "[Change Me]" in doc.name and doc.full_name:
        frappe.enqueue(
            "frappe.model.rename_doc.rename_doc",
            doctype=doc.doctype,
            old=doc.name,
            new=doc.full_name,
            force=False,
            show_alert=True,
        )

    if doc.user:
        # Update user's fields from contact
        user_fields = {
            "first_name": doc.first_name,
            "middle_name": doc.middle_name,
            "last_name": doc.last_name,
            "full_name": doc.full_name,
            "phone": doc.phone,
            "mobile_no": doc.mobile_no,
            "gender": doc.gender,
        }

        # Only update fields that have changed
        update_fields = {
            field: value
            for field, value in user_fields.items()
            if doc.has_value_changed(field) and value is not None
        }

        if update_fields:
            frappe.db.set_value("User", doc.user, update_fields)
