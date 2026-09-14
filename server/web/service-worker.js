"use strict";

const PUSH_VERSION = 1;
const MAX_REQUEST_ID = 128;
const SAFE_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

function pushPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || value.version !== PUSH_VERSION) return null;
  if ((value.lane !== "request" && value.lane !== "auth") || typeof value.request_id !== "string") return null;
  if (value.request_id.length === 0 || value.request_id.length > MAX_REQUEST_ID || !SAFE_REQUEST_ID.test(value.request_id)) return null;
  return { version: PUSH_VERSION, lane: value.lane, request_id: value.request_id };
}
function notificationTarget(value, origin = self.location.origin) {
  const payload = pushPayload(value);
  if (!payload) return null;
  return new URL(`/${payload.lane === "request" ? "r" : "a"}/${payload.request_id}`, origin).href;
}
function notificationTag(value) {
  const payload = pushPayload(value);
  return payload ? `${payload.lane}:${payload.request_id}` : null;
}

self.addEventListener("push", event => {
  let payload;
  try { payload = pushPayload(event.data?.json()); } catch { payload = null; }
  if (!payload) return;
  const body = payload.lane === "request" ? "A sudo approval needs your attention." : "Sudo authentication needs your attention.";
  event.waitUntil(self.registration.showNotification("Oshioki", {
    body,
    tag: notificationTag(payload),
    renotify: false,
    data: payload,
  }));
});

self.addEventListener("notificationclick", event => {
  const target = notificationTarget(event.notification?.data);
  event.notification?.close();
  if (!target) return;
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const exact = windows.find(client => {
      try { return new URL(client.url).href === target; } catch { return false; }
    });
    if (exact) return exact.focus();
    const sameOrigin = windows.find(client => {
      try { return new URL(client.url).origin === self.location.origin; } catch { return false; }
    });
    if (sameOrigin && typeof sameOrigin.navigate === "function") {
      try {
        const navigated = await sameOrigin.navigate(target);
        if (navigated && typeof navigated.focus === "function") return navigated.focus();
      } catch {
        // A closed or discarded client can reject navigation. Open the exact
        // target below so a notification tap never leaves the user on setup.
      }
    }
    return self.clients.openWindow(target);
  })());
});

if (typeof self !== "undefined") self.OshiokiPushWorker = { pushPayload, notificationTarget, notificationTag };
