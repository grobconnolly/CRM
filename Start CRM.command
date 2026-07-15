#!/bin/zsh
# Double-click this file to start the Finlete CRM and open it in your browser.
cd "$(dirname "$0")"
open http://localhost:4321
exec node server.js
