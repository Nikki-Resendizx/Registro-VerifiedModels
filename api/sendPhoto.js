// api/sendPhoto.js
import { createHmac, timingSafeEqual } from "node:crypto";

const ID_CANAL = "-1004459106029";
const MAX_BODY = 12 * 1024 * 1024;
const MAX_PHOTO = 10 * 1024 * 1024;
const MAX_AUTH_AGE = 10 * 60;
const recentSubmissions = new Map();

function jsonError(res, status, description) {
  return res.status(status).json({ ok: false, description });
}

function verifyTelegramInitData(initData, botToken) {
  if (typeof initData !== "string" || !initData || initData.length > 8192) {
    return { ok: false, reason: "Abre el formulario desde el bot de Telegram." };
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
    return { ok: false, reason: "Autenticación de Telegram inválida." };
  }

  params.delete("hash");
  params.delete("signature");
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = createHmac("sha256", "WebAppData").update(botToken).digest();
  const calculatedHash = createHmac("sha256", secretKey).update(dataCheckString).digest();
  const suppliedHash = Buffer.from(receivedHash, "hex");
  if (suppliedHash.length !== calculatedHash.length || !timingSafeEqual(suppliedHash, calculatedHash)) {
    return { ok: false, reason: "No se pudo verificar tu sesión de Telegram." };
  }

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(authDate) || authDate > now + 30 || now - authDate > MAX_AUTH_AGE) {
    return { ok: false, reason: "Tu sesión expiró. Cierra y vuelve a abrir el formulario desde Telegram." };
  }

  let user;
  try { user = JSON.parse(params.get("user") || "null"); } catch { user = null; }
  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0) {
    return { ok: false, reason: "No se pudo identificar tu cuenta de Telegram." };
  }
  return { ok: true, user };
}

function splitBuffer(buffer, delimiter) {
  const parts = [];
  let cursor = 0;
  while (true) {
    const index = buffer.indexOf(delimiter, cursor);
    if (index === -1) {
      parts.push(buffer.subarray(cursor));
      break;
    }
    parts.push(buffer.subarray(cursor, index));
    cursor = index + delimiter.length;
  }
  return parts;
}

function parseMultipart(buffer, contentType) {
  const match = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  const boundary = match && (match[1] || match[2]).trim();
  if (!boundary || boundary.length > 200) throw new Error("Formulario multipart inválido.");

  const delimiter = Buffer.from(`--${boundary}`);
  const parts = splitBuffer(buffer, delimiter);
  const fields = Object.create(null);
  let photo = null;

  for (let part of parts) {
    if (!part.length || part.equals(Buffer.from("--")) || part.subarray(0, 2).toString() === "--") continue;
    if (part.subarray(0, 2).toString() === "\r\n") part = part.subarray(2);
    if (part.subarray(-2).toString() === "\r\n") part = part.subarray(0, -2);
    const separator = part.indexOf(Buffer.from("\r\n\r\n"));
    if (separator < 0) continue;
    const headers = part.subarray(0, separator).toString("latin1");
    const data = part.subarray(separator + 4);
    const disposition = /content-disposition:\s*form-data;[^\r\n]*name="([^"]+)"(?:;\s*filename="([^"]*)")?/i.exec(headers);
    if (!disposition) continue;
    const name = disposition[1];
    const filename = disposition[2];
    if (filename !== undefined) {
      const typeMatch = /content-type:\s*([^\r\n]+)/i.exec(headers);
      if (name !== "photo" || photo) throw new Error("Archivo adjunto no válido.");
      photo = { filename: filename || "foto.jpg", type: (typeMatch?.[1] || "").trim().toLowerCase(), data };
    } else {
      if (data.length > 8192) throw new Error("Uno de los campos supera el tamaño permitido.");
      fields[name] = data.toString("utf8");
    }
  }
  return { fields, photo };
}

function cleanText(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return jsonError(res, 405, "Método no permitido.");
  }

  const botToken = process.env.BOT_TOKEN;
  if (!botToken) return jsonError(res, 500, "El servicio no está configurado.");

  // Evita que páginas de otros dominios utilicen el endpoint desde un navegador.
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (!origin || !host) return jsonError(res, 403, "Origen no autorizado.");
  try {
    const originUrl = new URL(origin);
    if (originUrl.protocol !== "https:" || originUrl.host.toLowerCase() !== host.toLowerCase()) {
      return jsonError(res, 403, "Origen no autorizado.");
    }
  } catch {
    return jsonError(res, 403, "Origen no autorizado.");
  }

  const auth = verifyTelegramInitData(req.headers["x-telegram-init-data"], botToken);
  if (!auth.ok) return jsonError(res, 401, auth.reason);

  const contentType = req.headers["content-type"] || "";
  if (!/^multipart\/form-data\s*;/i.test(contentType)) {
    return jsonError(res, 415, "Formato de envío no válido.");
  }

  const declaredLength = Number(req.headers["content-length"] || 0);
  if (declaredLength > MAX_BODY) return jsonError(res, 413, "El formulario supera el tamaño permitido.");

  try {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_BODY) return jsonError(res, 413, "El formulario supera el tamaño permitido.");
      chunks.push(chunk);
    }

    const { fields, photo } = parseMultipart(Buffer.concat(chunks), contentType);
    const nombreVentas = cleanText(fields.nombreVentas, 60);
    const usuario = cleanText(fields.usuario, 33);
    const edadText = cleanText(fields.edad, 3);
    const edad = Number(edadText);
    const nacionalidad = cleanText(fields.nacionalidad, 50);
    const canalFree = cleanText(fields.canalFree, 120);
    const descripcion = cleanText(fields.descripcion, 300);

    let servicios;
    try { servicios = JSON.parse(fields.servicios || "[]"); } catch { servicios = null; }
    if (!nombreVentas || !/^@[A-Za-z0-9_]{5,32}$/.test(usuario) ||
        !/^\d{1,3}$/.test(edadText) || !Number.isInteger(edad) || edad < 18 || edad > 99 ||
        !nacionalidad || !descripcion || !Array.isArray(servicios) ||
        servicios.length < 1 || servicios.length > 14 ||
        servicios.some(item => typeof item !== "string" || item.length > 80)) {
      return jsonError(res, 400, "Revisa los datos. La edad debe ser de 18 años o más y todos los campos deben ser válidos.");
    }

    let channelUrl;
    try { channelUrl = new URL(canalFree); } catch { channelUrl = null; }
    if (!channelUrl || channelUrl.protocol !== "https:" ||
        !["t.me", "www.t.me", "telegram.me", "www.telegram.me"].includes(channelUrl.hostname.toLowerCase())) {
      return jsonError(res, 400, "El enlace del canal debe ser una dirección válida de Telegram (https://t.me/...).");
    }

    if (!photo || !photo.data.length || photo.data.length > MAX_PHOTO ||
        !["image/jpeg", "image/png", "image/webp"].includes(photo.type)) {
      return jsonError(res, 400, "Adjunta una foto JPG, PNG o WEBP de máximo 10 MB.");
    }

    // Límite por usuario de Telegram (mejor esfuerzo entre instancias serverless).
    const now = Date.now();
    const lastSubmission = recentSubmissions.get(auth.user.id);
    if (lastSubmission && now - lastSubmission < 60_000) {
      return jsonError(res, 429, "Ya recibimos un envío reciente. Espera un minuto antes de volver a intentarlo.");
    }
    recentSubmissions.set(auth.user.id, now);
    for (const [id, timestamp] of recentSubmissions) {
      if (now - timestamp > 5 * 60_000) recentSubmissions.delete(id);
    }

    const perfilNombre = [auth.user.first_name, auth.user.last_name].filter(Boolean).join(" ") || "Sin nombre";
    const tgUsername = auth.user.username ? "@" + auth.user.username : "sin username";
    const idioma = cleanText(auth.user.language_code || "desconocido", 20);
    const fechaHora = new Date().toLocaleString("es-MX", { timeZone: "America/Mexico_City", hour12: true });
    const listaServs = servicios.map(s => `• ${s.replace(/^\S+\s*/, "")}`).join("\n");

    const caption = `💎 𝙉𝙐𝙀𝙑𝘼 𝘾𝙃𝙄𝘾𝘼 𝙍𝙀𝙂𝙄𝙎𝙏𝙍𝘼𝘿𝘼 💎

👑 𝐍𝐎𝐌𝐁𝐑𝐄 𝐐𝐔𝐄 𝐔𝐒𝐀 𝐏𝐀𝐑𝐀 𝐕𝐄𝐍𝐓𝐀𝐒.
${nombreVentas}

👤 𝐔𝐒𝐔𝐀𝐑𝐈𝐎 𝐃𝐄 𝐋𝐀 𝐌𝐎𝐃𝐄𝐋𝐎.
${usuario}

🔞 𝐄𝐃𝐀𝐃 𝐃𝐄 𝐋𝐀 𝐌𝐎𝐃𝐄𝐋𝐎.
${edad}

🌐 𝐍𝐀𝐂𝐈𝐎𝐍𝐀𝐋𝐈𝐃𝐀𝐃
${nacionalidad}

👸🏻 𝐃𝐄𝐒𝐂𝐑𝐈𝐏𝐂𝐈𝐎𝐍.
${descripcion}

📝 𝐋𝐈𝐒𝐓𝐀 𝐃𝐄 𝐒𝐄𝐑𝐕𝐈𝐂𝐈𝐎𝐒
${listaServs}

🔗 𝐋𝐈𝐍𝐊 𝐃𝐄𝐋 𝐂𝐀𝐍𝐀𝐋 𝐅𝐑𝐄𝐄
${canalFree}

━━━━━━━━━━━━━━━
👤 Info de quien registró:
- Perfil: ${perfilNombre}
- Username: ${tgUsername}
- ID: ${auth.user.id}
- Fecha y hora: ${fechaHora}
- Idioma: ${idioma}`;

    if (caption.length > 1024) {
      return jsonError(res, 400, "La descripción o los servicios son demasiado extensos. Acórtalos e inténtalo de nuevo.");
    }

    const telegramForm = new FormData();
    telegramForm.append("chat_id", ID_CANAL);
    telegramForm.append("caption", caption);
    telegramForm.append("photo", new Blob([photo.data], { type: photo.type }), photo.filename.slice(0, 100));

    const telegramResponse = await fetch(`https://api.telegram.org/bot${botToken}/sendPhoto`, {
      method: "POST",
      body: telegramForm,
    });
    const telegramData = await telegramResponse.json();
    if (!telegramResponse.ok || !telegramData.ok) {
      console.error("Telegram sendPhoto failed:", telegramData.error_code || telegramResponse.status);
      return jsonError(res, 502, "Telegram no pudo recibir el registro. Inténtalo de nuevo más tarde.");
    }
    return res.status(200).json({ ok: true, description: "Registro enviado correctamente." });
  } catch (error) {
    console.error("sendPhoto error:", error?.message || "unknown");
    return jsonError(res, 500, "Ocurrió un error al procesar el registro.");
  }
}

export const config = {
  api: { bodyParser: false },
};
