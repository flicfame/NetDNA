const TOKEN_KEY = "netdna_token";
const USER_KEY = "netdna_user";

export interface AuthUser {
  id: number;
  username: string;
  fullName: string;
  role: string;
  roleLabel: string;
  permissions: string[];
}

export const Auth = {
  getToken: (): string | null => localStorage.getItem(TOKEN_KEY),
  getUser: (): AuthUser | null => {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  },
  isLoggedIn: (): boolean => !!localStorage.getItem(TOKEN_KEY),
  can: (permission: string): boolean => {
    const user = Auth.getUser();
    return (user?.permissions || []).includes(permission);
  },
  login: (token: string, user: AuthUser) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  logout: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = "/";
  },
};

export async function apiWithAuth(method: string, path: string, body?: unknown) {
  const token = Auth.getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const opts: RequestInit = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  const resp = await fetch("/api/v1" + path, opts);
  if (resp.status === 401) {
    Auth.logout();
    throw new Error("Session expired");
  }
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ message: "Request failed" }));
    throw new Error(err.message || err.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}
