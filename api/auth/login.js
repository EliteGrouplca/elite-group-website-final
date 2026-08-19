import { createSessionToken, noStore, passwordsMatch, sessionCookie } from '../_auth.js';

export default async function handler(req, res) {
  noStore(res);
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    if (!passwordsMatch(req.body?.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    res.setHeader('Set-Cookie', sessionCookie(createSessionToken()));
    return res.status(200).json({ authenticated: true });
  } catch (error) {
    console.error('Dashboard login configuration error:', error.message);
    return res.status(500).json({ error: 'Authentication is unavailable' });
  }
}
