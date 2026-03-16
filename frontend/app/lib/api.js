export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:8000";

export async function fetchJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${path}`);
  }
  return response.json();
}

export async function postJson(path, body) {
  return fetchJson(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}
