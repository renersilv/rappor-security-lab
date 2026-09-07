import { NextResponse } from "next/server";

import { cookieOptions, getState, responseHeaders } from "./lib/states.mjs";

export function proxy(request) {
  if (!["GET", "HEAD"].includes(request.method)) {
    return new NextResponse(null, {
      status: 405,
      headers: { allow: "GET, HEAD", "cache-control": "no-store" },
    });
  }

  const state = getState();
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const headers = responseHeaders(state, nonce);
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  if (headers["content-security-policy"]) {
    requestHeaders.set("content-security-policy", headers["content-security-policy"]);
  }
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  for (const [name, value] of Object.entries(headers)) {
    response.headers.set(name, value);
  }
  response.cookies.set({
    name: "rappor_lab_notice",
    value: "synthetic",
    ...cookieOptions(state),
  });
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
