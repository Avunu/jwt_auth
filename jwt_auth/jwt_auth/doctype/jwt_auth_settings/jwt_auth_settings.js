// Copyright (c) 2024, Avunu LLC and contributors
// For license information, please see license.txt

// frappe.ui.form.on("JWT Auth Settings", {
// 	refresh(frm) {

// 	},
// });

frappe.realtime.on("debug", (data) => {
    console.log(data);
});