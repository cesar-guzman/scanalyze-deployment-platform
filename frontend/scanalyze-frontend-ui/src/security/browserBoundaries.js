const FORMULA_PREFIX = /^[\u0000-\u0020]*[=+\-@]/u;
const SAFE_FILENAME = /[^A-Za-z0-9._-]+/gu;

export class BrowserBoundaryError extends Error {
  constructor(code = 'BROWSER_BOUNDARY_REJECTED') {
    super(code);
    this.name = 'BrowserBoundaryError';
    this.code = code;
  }
}

export const requireHttpsUrl = (value) => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 8192) {
    throw new BrowserBoundaryError();
  }

  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') {
      throw new BrowserBoundaryError();
    }
    return parsed.toString();
  } catch (error) {
    if (error instanceof BrowserBoundaryError) throw error;
    throw new BrowserBoundaryError();
  }
};

export const openExternalHttpsUrl = (value) => {
  const url = requireHttpsUrl(value);
  const opened = window.open(url, '_blank', 'noopener,noreferrer');
  if (opened) opened.opener = null;
};

export const csvCell = (value) => {
  const normalized = String(value ?? '').replace(/\r\n?/gu, '\n');
  const neutralized = FORMULA_PREFIX.test(normalized) ? `'${normalized}` : normalized;
  return `"${neutralized.replace(/"/gu, '""')}"`;
};

export const safeDownloadFilename = (value, fallback) => {
  const safeFallback = String(fallback).replace(SAFE_FILENAME, '_').slice(0, 128);
  if (typeof value !== 'string') return safeFallback;

  const normalized = value
    .normalize('NFKD')
    .replace(/\p{M}+/gu, '')
    .replace(SAFE_FILENAME, '_')
    .replace(/^\.+/u, '')
    .slice(0, 128);
  return normalized || safeFallback;
};
