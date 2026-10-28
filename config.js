// Public settings only. Safe to commit: the publishable key is meant to be public,
// and the database rules (schema.sql) decide who can read or write anything.
// NEVER put a "secret" or "service_role" key in this file.
window.DHS_CONFIG = {
  url: "https://YOUR-PROJECT.supabase.co",   // Supabase > Project Settings > API > Project URL
  key: "sb_publishable_YOUR_KEY",            // Supabase > Project Settings > API Keys > Publishable key
  ntfy: "https://ntfy.sh"                    // ntfy server
};
