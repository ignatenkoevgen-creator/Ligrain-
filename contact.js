export async function onRequestPost(context) {
  const { request, env } = context;

  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });

  try {
    const form = await request.formData();

    // Honeypot: bots often fill hidden fields.
    if (String(form.get("website") || "").trim() !== "") {
      return json({ ok: true });
    }

    const clean = (name, max = 3000) =>
      String(form.get(name) || "").trim().slice(0, max);

    const origin = clean("origin", 120);
    const destination = clean("destination", 120);
    const cargo = clean("cargo", 160);
    const volume = clean("volume", 80);
    const date = clean("date", 40);
    const modeRaw = clean("mode", 40);
    const name = clean("name", 160);
    const email = clean("email", 180);
    const phone = clean("phone", 80);
    const details = clean("details", 3000);

    if (!origin || !destination || !cargo || !name || !email) {
      return json({ ok: false, message: "Please complete all required fields." }, 422);
    }

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!emailOk) {
      return json({ ok: false, message: "Please enter a valid email address." }, 422);
    }

    const allowedModes = new Set(["Not sure", "Rail", "Road", "Multimodal"]);
    const mode = allowedModes.has(modeRaw) ? modeRaw : "Not sure";

    const subject = `Ligrain shipment request: ${origin.replace(/[\r\n]+/g, " ")} → ${destination.replace(/[\r\n]+/g, " ")}`;

    const text = [
      "New shipment request from ligrain.net",
      "",
      `Origin: ${origin}`,
      `Destination: ${destination}`,
      `Cargo: ${cargo}`,
      `Volume / MT: ${volume || "-"}`,
      `Preferred shipment date: ${date || "-"}`,
      `Transport mode: ${mode}`,
      `Name / Company: ${name}`,
      `Email: ${email}`,
      `Phone: ${phone || "-"}`,
      "",
      "Additional details:",
      details || "-",
      "",
      "Submitted from: https://ligrain.net/contact.html",
    ].join("\n");

    const html = `
      <h2>New shipment request</h2>
      <table cellpadding="7" cellspacing="0" style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px">
        <tr><td><b>Origin</b></td><td>${escapeHtml(origin)}</td></tr>
        <tr><td><b>Destination</b></td><td>${escapeHtml(destination)}</td></tr>
        <tr><td><b>Cargo</b></td><td>${escapeHtml(cargo)}</td></tr>
        <tr><td><b>Volume / MT</b></td><td>${escapeHtml(volume || "-")}</td></tr>
        <tr><td><b>Date</b></td><td>${escapeHtml(date || "-")}</td></tr>
        <tr><td><b>Mode</b></td><td>${escapeHtml(mode)}</td></tr>
        <tr><td><b>Name / Company</b></td><td>${escapeHtml(name)}</td></tr>
        <tr><td><b>Email</b></td><td>${escapeHtml(email)}</td></tr>
        <tr><td><b>Phone</b></td><td>${escapeHtml(phone || "-")}</td></tr>
      </table>
      <h3>Additional details</h3>
      <p style="white-space:pre-wrap">${escapeHtml(details || "-")}</p>
    `;

    if (!env.CLOUDFLARE_ACCOUNT_ID || !env.CLOUDFLARE_EMAIL_API_TOKEN) {
      console.error("Missing Cloudflare Email Service secrets.");
      return json({ ok: false, message: "Email service is not configured." }, 500);
    }

    const apiUrl = `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/email/sending/send`;

    const emailResponse = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.CLOUDFLARE_EMAIL_API_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        to: "evgen@ligrain.net",
        from: "website@ligrain.net",
        subject,
        text,
        html,
        reply_to: email,
      }),
    });

    const result = await emailResponse.json().catch(() => ({}));

    if (!emailResponse.ok || result?.success === false) {
      console.error("Cloudflare Email Service error:", JSON.stringify(result));
      return json({ ok: false, message: "Unable to send your request right now." }, 502);
    }

    return json({ ok: true });
  } catch (error) {
    console.error("Contact form error:", error);
    return json({ ok: false, message: "Unable to process your request." }, 500);
  }
}

export async function onRequest(context) {
  return new Response("Method Not Allowed", {
    status: 405,
    headers: { Allow: "POST" },
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
