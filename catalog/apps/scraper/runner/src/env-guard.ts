// Imported first by the server so these values are in place before Crawlee reads its configuration.
// Crawlee v3 lets environment variables beat constructor options, so the safe values are forced here.

const FORCED: Record<string, string> = {
  CRAWLEE_PERSIST_STORAGE: 'false',
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1',
};

// Variables that would weaken the browser sandbox or route traffic around sealed-egress.
const REMOVED = [
  'CRAWLEE_DISABLE_BROWSER_SANDBOX',
  'MOZ_DISABLE_CONTENT_SANDBOX',
  'MOZ_DISABLE_GMP_SANDBOX',
  'MOZ_DISABLE_RDD_SANDBOX',
  'MOZ_DISABLE_SOCKET_PROCESS_SANDBOX',
  'MOZ_DISABLE_UTILITY_SANDBOX',
  'MOZ_DISABLE_VR_SANDBOX',
  'MOZ_SANDBOX_LOGGING',
  'PLAYWRIGHT_DISABLE_FORCED_CHROMIUM_PROXIED_LOOPBACK',
];

export function hardenEnv(env: NodeJS.ProcessEnv): string[] {
  const changed: string[] = [];
  for (const [key, value] of Object.entries(FORCED)) {
    if (env[key] !== value) {
      env[key] = value;
      changed.push(key);
    }
  }
  for (const key of REMOVED) {
    if (key in env) {
      delete env[key];
      changed.push(key);
    }
  }
  return changed;
}

hardenEnv(process.env);
