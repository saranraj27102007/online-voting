// Middleware to protect admin routes
// NOTE: All routes protected by this middleware are JSON API routes mounted
// under /api/admin — so we always return 401 JSON, never an HTML redirect.
// (req.path inside the router is e.g. "/stats", never "/api/admin/stats",
//  so the old req.path.includes('/api/') check always evaluated to false.)
function requireAdminAuth(req, res, next) {
  if (!req.session || !req.session.adminId) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }

  // Refresh session on activity
  req.session.lastActivity = Date.now();
  next();
}

// Middleware to check idle timeout (2 hours)
function checkIdleTimeout(req, res, next) {
  if (!req.session || !req.session.adminId) return next();

  const now = Date.now();
  const lastActivity = req.session.lastActivity || now;
  const IDLE_TIMEOUT = 2 * 60 * 60 * 1000; // 2 hours

  if (now - lastActivity > IDLE_TIMEOUT) {
    req.session.destroy();
    return res.status(401).json({ error: 'Session expired due to inactivity.' });
  }

  req.session.lastActivity = now;
  next();
}

module.exports = { requireAdminAuth, checkIdleTimeout };
