import { getApiClient } from './client';

// ─── Types ─────────────────────────────────────

export interface AddonRegistryEntry {
  addonId: string;
  displayName: string;
  description: string;
  icon: string;
  uiPath: string;
  componentKey: string;
  apiBasePath: string;
  runtime: 'lambda' | 'inprocess' | 'disabled';
  version: string;
  enabled: boolean;
}

// ─── API Client ────────────────────────────────

const REGISTRY_PATH = '/addons/registry';

export const addonsRegistryApi = {
  /**
   * Fetch the addon registry.
   * Returns an empty array on failure (safe fallback).
   */
  getRegistry: async (): Promise<AddonRegistryEntry[]> => {
    try {
      const client = getApiClient();
      const resp = await client.get(REGISTRY_PATH);
      return (resp.data as AddonRegistryEntry[]) || [];
    } catch {
      // Registry unavailable — fallback to empty (in-process behavior)
      return [];
    }
  },
};
