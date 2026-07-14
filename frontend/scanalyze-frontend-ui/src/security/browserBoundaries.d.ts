export class BrowserBoundaryError extends Error {
  readonly code: string;
  constructor(code?: string);
}

export function requireHttpsUrl(value: unknown): string;
export function openExternalHttpsUrl(value: unknown): void;
export function csvCell(value: unknown): string;
export function safeDownloadFilename(value: unknown, fallback: string): string;
