# Dilijan Guesthouse Bookings

A mobile-first multi-user booking manager based on the uploaded single-file prototype.

## What changed from the prototype

- Real Python backend with SQLite database (no Claude artifact database dependency).
- Username/password accounts with owner and staff roles.
- First-run owner account setup.
- Owner-only Team tab to create staff accounts and reset passwords.
- All users share the same booking data.
- Server-Sent Events (SSE) for live updates across phones/browsers.
- Server-side overlap detection with a confirm-and-save-anyway flow.
- Cancelled bookings remain in the database, appear faded/crossed out, and no longer block dates.
- Delete is permanent and asks for confirmation.
- Trilingual interface: English, Russian, Armenian.
- Language, theme, and booking-entry name are remembered locally.
- PWA manifest/service worker for easier phone home-screen installation.

## Run locally

Requires Python 3.10+.

```bash
cd dilijan_guesthouse_app
python3 server.py
```

Open `http://127.0.0.1:8000`.

The first visitor is shown a one-time owner setup screen. After that, use the owner's Team tab to create employee accounts.

## Production notes

Use HTTPS in production and set `GH_COOKIE_SECURE=1`.
For internet hosting, run the app behind a reverse proxy (for example Nginx/Caddy) and keep the SQLite `data/guesthouse.sqlite3` file on persistent storage.

Environment variables:

- `GH_HOST` (default `127.0.0.1`)
- `GH_PORT` (default `8000`)
- `GH_DB_PATH` (default `./data/guesthouse.sqlite3`)
- `GH_SESSION_DAYS` (default `30`)
- `GH_COOKIE_SECURE=1` when served over HTTPS
