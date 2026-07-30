export class RuntimeConfigError extends Error {
  readonly code: string;
  constructor(code?: string);
}

export function parseRuntimeConfig(value: unknown): unknown;
