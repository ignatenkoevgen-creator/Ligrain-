export async function onRequestPost(context) {
 const { request, env } = context;

 const json = (body, status = 200) =>
   new Response(JSON.stringify(body), {
     status,
     headers: {
       "Content-Type": "application/json; charset=utf-8",
       "Cache-Control": "no-store",
     },
   });

 try {
   const form = await request.formData();

   // Honeypot anti-spam
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

   if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
     return json({ ok: false, message: "Please enter a valid email address." }, 422);
   }

   if (!env.RESEND_API_KEY) {
     return json({ ok: false, message: "Email service is not configured." }, 500);
   }

   const allowedModes = new Set(["Not sure", "Rail", "Road", "Multimodal"]);
   const mode = allowedModes.has(modeRaw) ? modeRaw : "Not sure";

   const subject = `Ligrain shipment request: ${origin} â ${destination}`;

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
   ].join("\n");

   const response = await fetch("https://api.resend.com/emails", {
     method: "POST",
     headers: {
       Authorization: `Bearer ${env.RESEND_API_KEY}`,
       "Content-Type": "application/json",
     },
     body: JSON.stringify({
       from: "Ligrain Website <website@ligrain.net>",
       to: ["evgen@ligrain.net"],
       subject,
       text,
       reply_to: email,
     }),
   });

   const result = await response.json().catch(() => ({}));

   if (!response.ok) {
     console.error("Resend error:", JSON.stringify(result));
     return json({ ok: false, message: "Unable to send your request right now." }, 502);
   }

   return json({ ok: true });
 } catch (error) {
   console.error("Contact form error:", error);
   return json({ ok: false, message: "Unable to process your request." }, 500);
 }
}

export async function onRequest() {
 return new Response("Method Not Allowed", {
   status: 405,
   headers: { Allow: "POST" },
 });
}

