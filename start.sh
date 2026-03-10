#!/bin/bash
echo ""
echo " =========================================="
echo "  VoteSecure - Starting Server"
echo " =========================================="
echo ""

if [ ! -d "node_modules" ]; then
  echo " [!] node_modules not found. Running npm install..."
  echo ""
  npm install
  echo ""
fi

echo " Starting server..."
echo " Open your browser at: http://localhost:3000"
echo ""
node server.js
