import { isAuthenticated, noStore } from '../_auth.js';

export default function handler(req, res) {
  noStore(res);
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    return res.status(200).json({ authenticated: isAuthenticated(req) });
  } catch (error) {
    console.error('Dashboard session configuration error:', error.message);
    return res.status(500).json({ authenticated: false });
  }
}
