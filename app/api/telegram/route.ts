export async function POST(req: Request) {
  const body = await req.json()
  const chatId = body.message?.chat?.id
  if (!chatId) return new Response('OK')
  const text = body.message?.text || ''
  const ref = text.split(' ')[1] || 'direct'
  const TOKEN = process.env.TELEGRAM_BOT_TOKEN

  await fetch(`https://api.telegram.org/bot${TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: `🛡️ HAWK Shield LIVE!\n\nYou joined with: ${ref}\n\nYour own link:\nhttps://t.me/HAWKShield_bot?start=${Math.random().toString(36).slice(2, 8)}\n\nEverybody gets unique link like your gwiksq238ms — this bot go track am now!`
    })
  })
  return new Response('OK')
}
export async function GET() { return new Response('HAWK Shield Bot Active') }
