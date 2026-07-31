/* Card Vault — iCloud sync configuration.
   Fill these in from the CloudKit Dashboard, then redeploy. Until you do,
   the app runs exactly as before: fully offline, sync UI shows "not configured".

   1. developer.apple.com → Certificates, Identifiers & Profiles → Identifiers
      → iCloud Containers → create e.g. "iCloud.com.vishalparwani.cardvault".
   2. icloud.developer.apple.com/dashboard → pick that container
      → Settings → Tokens → "+" under API Tokens.
        - Sign-in callback / redirect: https://cardvault.vishalparwani.com/
        - Copy the token string into apiToken below.
   3. Same page → Allowed Origins: add https://cardvault.vishalparwani.com
   4. Ship with environment "development" while testing. Once it works, use
      CloudKit Dashboard → Deploy Schema to Production, then switch to
      "production" here. The two environments hold SEPARATE data.

   The API token is a public client token by design — Apple scopes it to the
   origins you listed above, so committing it to a public repo is expected.
   It grants nothing on its own: every request still needs the signed-in
   user's Apple ID, and it only ever reaches that user's own private database.
*/
window.CARD_VAULT_SYNC = {
  containerIdentifier: "PASTE_YOUR_ICLOUD_CONTAINER_ID",
  apiToken: "PASTE_YOUR_CLOUDKIT_WEB_API_TOKEN",
  environment: "development", // "development" | "production"
};
