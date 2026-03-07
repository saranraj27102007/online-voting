const express = require('express');
const router = express.Router();

// Auth status check
router.get('/status', (req, res) => {
  res.json({
    adminLoggedIn: !!(req.session && req.session.adminId),
    voterAuthenticated: !!(req.session && req.session.voterAuthenticated)
  });
});

module.exports = router;
