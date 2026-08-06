import {
  parseRuntimeConfig,
  parseStrictJson,
  RuntimeConfigError,
  type ParsedRuntimeConfig,
} from './runtime.js';

export type AppConfig = ParsedRuntimeConfig;

const CONFIG_TIMEOUT_MS = 5_000;
const MAX_CONFIG_BYTES = 65_536;

let config: AppConfig | null = null;
let pendingConfig: Promise<AppConfig> | null = null;

const isAbortError = (error: unknown): boolean => (
  error instanceof DOMException
    ? error.name === 'AbortError'
    : Boolean(error && typeof error === 'object' && 'name' in error && error.name === 'AbortError')
);

const readBoundedResponse = async (
  response: Response,
  controller: AbortController,
): Promise<string> => {
  const declaredLength = response.headers.get('Content-Length');
  if (
    declaredLength !== null
    && /^[0-9]+$/.test(declaredLength)
    && Number(declaredLength) > MAX_CONFIG_BYTES
  ) {
    controller.abort();
    throw new RuntimeConfigError();
  }

  const reader = response.body?.getReader();
  if (!reader) throw new RuntimeConfigError('RUNTIME_CONFIG_UNAVAILABLE');

  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_CONFIG_BYTES) {
      controller.abort();
      try {
        await reader.cancel();
      } catch {
        // The abort already closed the body; never project transport details.
      }
      throw new RuntimeConfigError();
    }
    chunks.push(value);
  }
  if (size === 0) throw new RuntimeConfigError();

  const content = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    content.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(content);
  } catch {
    throw new RuntimeConfigError();
  }
};

const loadConfigOnce = async (): Promise<AppConfig> => {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), CONFIG_TIMEOUT_MS);
  try {
    const response = await fetch('/config.json', {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!response.ok) throw new RuntimeConfigError('RUNTIME_CONFIG_UNAVAILABLE');

    const serialized = await readBoundedResponse(response, controller);

    const parsed = parseStrictJson(serialized);
    return parseRuntimeConfig(parsed, { origin: window.location.origin });
  } catch (error: unknown) {
    if (error instanceof RuntimeConfigError) throw error;
    if (isAbortError(error)) throw new RuntimeConfigError('RUNTIME_CONFIG_TIMEOUT');
    throw new RuntimeConfigError('RUNTIME_CONFIG_UNAVAILABLE');
  } finally {
    window.clearTimeout(timeout);
  }
};

export const loadConfig = (): Promise<AppConfig> => {
  if (config) return Promise.resolve(config);
  if (pendingConfig) return pendingConfig;

  pendingConfig = loadConfigOnce()
    .then((loaded) => {
      config = loaded;
      return loaded;
    })
    .finally(() => {
      pendingConfig = null;
    });
  return pendingConfig;
};

export const getConfig = (): AppConfig => {
  if (!config) throw new RuntimeConfigError('RUNTIME_CONFIG_NOT_LOADED');
  return config;
};

export { RuntimeConfigError };
