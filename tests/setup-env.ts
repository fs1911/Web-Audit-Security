// Gemeinsame Testumgebung. Keine echten Secrets.
process.env.DATABASE_URL ??= "postgres://webaudit:webaudit@localhost:5432/webaudit_test";
process.env.APP_ENCRYPTION_KEY ??= Buffer.alloc(32, 7).toString("base64");
process.env.RUNNER_CALLBACK_SECRET ??= "test-callback-secret-0123456789abcdef";
process.env.RUNNER_SHARED_SECRET ??= "test-shared-secret-0123456789abcdef";
process.env.STORAGE_DIR ??= "./var/test-storage";
