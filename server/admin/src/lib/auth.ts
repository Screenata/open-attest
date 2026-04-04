import { createContext, useContext } from 'react';

export type AuthState = {
  type: 'admin_secret' | 'api_key';
  value: string;
} | null;

const STORAGE_KEY = 'open_attest_auth';

export function getStoredAuth(): AuthState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && parsed.type && parsed.value) return parsed;
    return null;
  } catch {
    return null;
  }
}

export function setStoredAuth(auth: AuthState) {
  if (auth) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
  } else {
    localStorage.removeItem(STORAGE_KEY);
  }
}

export function clearStoredAuth() {
  localStorage.removeItem(STORAGE_KEY);
}

export interface AuthContextType {
  auth: AuthState;
  setAuth: (auth: AuthState) => void;
  logout: () => void;
  isAdmin: boolean;
}

export const AuthContext = createContext<AuthContextType>({
  auth: null,
  setAuth: () => {},
  logout: () => {},
  isAdmin: false,
});

export function useAuth() {
  return useContext(AuthContext);
}
