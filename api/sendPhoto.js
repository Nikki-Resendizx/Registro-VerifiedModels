// api/sendPhoto.js
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, description: 'Method not allowed' });
  }

  // Vercel guarda el token aquí, no en el código
  const BOT_TOKEN = process.env.BOT_TOKEN;
  const ID_CANAL = "-1004459106029";

  if (!BOT_TOKEN) {
    return res.status(500).json({ ok: false, description: 'BOT_TOKEN no configurado en Vercel' });
  }

  try {
    // Leemos lo que manda tu WebApp (FormData con foto + caption)
    const contentType = req.headers['content-type'] || '';
    
    // Necesitamos reenviar el body tal cual a Telegram
    // Vercel no parsea FormData automático, lo pasamos como buffer
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const buffer = Buffer.concat(chunks);

    const telegramRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto?chat_id=${ID_CANAL}`, {
      method: 'POST',
      headers: {
        'Content-Type': contentType,
      },
      body: buffer,
    });

    const data = await telegramRes.json();
    return res.status(200).json(data);

  } catch (e) {
    return res.status(500).json({ ok: false, description: e.message });
  }
}

export const config = {
  api: {
    bodyParser: false, // importante para que llegue la foto
  },
};
