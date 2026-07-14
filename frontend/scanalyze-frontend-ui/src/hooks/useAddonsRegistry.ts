import { useState, useEffect, useCallback, useRef } from 'react';
import { addonsRegistryApi } from '../api/addonsRegistryApi';
import type { AddonRegistryEntry } from '../api/addonsRegistryApi';

// Cache TTL — don't refetch registry more often than this
const CACHE_TTL_MS = 60_000; // 60 seconds
const INPROCESS_PATHS: Record<string, string> = {
  'employee-profiles': '/addons/employee-profiles',
};

interface UseAddonsRegistryResult {
  addons: AddonRegistryEntry[];
  loading: boolean;
  error: string | null;
  getApiBasePath: (addonId: string) => string;
  isAddonEnabled: (addonId: string) => boolean;
  refetch: () => void;
}

// Module-level cache shared across all hook instances
let _cache: AddonRegistryEntry[] | null = null;
let _cacheTime = 0;

/**
 * Hook to load the addon registry with caching and safe fallback.
 *
 * - If registry fails, all addons fall back to in-process paths.
 * - If an addon is disabled or runtime=inprocess, uses the in-process base path.
 * - Only uses Lambda v2 path if explicitly enabled with runtime=lambda.
 */
export function useAddonsRegistry(): UseAddonsRegistryResult {
  const [addons, setAddons] = useState<AddonRegistryEntry[]>(_cache || []);
  const [loading, setLoading] = useState(!_cache);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const fetchRegistry = useCallback(async () => {
    const now = Date.now();
    if (_cache && now - _cacheTime < CACHE_TTL_MS) {
      setAddons(_cache);
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const result = await addonsRegistryApi.getRegistry();
      if (mountedRef.current) {
        _cache = result;
        _cacheTime = Date.now();
        setAddons(result);
        setError(null);
      }
    } catch {
      if (mountedRef.current) {
        setError('Failed to load addon registry');
        // Keep using cached data or empty
        setAddons(_cache || []);
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    fetchRegistry();
    return () => {
      mountedRef.current = false;
    };
  }, [fetchRegistry]);

  const getApiBasePath = useCallback(
    (addonId: string): string => {
      const entry = addons.find((a) => a.addonId === addonId);

      // If no entry found, or addon is disabled, or runtime is inprocess → use in-process path
      if (!entry || !entry.enabled || entry.runtime !== 'lambda') {
        return INPROCESS_PATHS[addonId] || `/addons/${addonId}`;
      }

      // Lambda runtime active — use the registry's apiBasePath
      return entry.apiBasePath;
    },
    [addons],
  );

  const isAddonEnabled = useCallback(
    (addonId: string): boolean => {
      const entry = addons.find((a) => a.addonId === addonId);
      return entry?.enabled ?? false;
    },
    [addons],
  );

  return { addons, loading, error, getApiBasePath, isAddonEnabled, refetch: fetchRegistry };
}
