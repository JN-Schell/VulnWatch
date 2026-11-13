let csrfToken = "";
export function setCSRF(token: string) {
  csrfToken = token;
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  if (options.method && options.method !== "GET")
    headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(`/api${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const body = await response
      .json()
      .catch(() => ({ detail: "Service unavailable" }));
    if (response.status === 401)
      window.dispatchEvent(new Event("session-expired"));
    throw new Error(
      typeof body.detail === "string"
        ? body.detail
        : "Request validation failed",
    );
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

export function date(value: string | null, short = false) {
  if (!value) return "—";
  return new Date(
    /^\d{4}-\d{2}-\d{2}$/.test(value)
      ? `${value}T12:00:00`
      : value.endsWith("Z") || /[+-]\d\d:\d\d$/.test(value)
        ? value
        : `${value}Z`,
  ).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    ...(short ? {} : { year: "numeric" }),
  });
}
