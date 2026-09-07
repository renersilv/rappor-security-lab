import { headers } from "next/headers";
import Script from "next/script";
import { connection } from "next/server";

import LabClient from "./lab-client.jsx";
import { getState } from "../lib/states.mjs";

export default async function Page() {
  await connection();
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  const state = getState();
  return (
    <main
      data-framework="Next.js"
      data-generator="Lovable"
      data-host-profile="Vercel"
      data-lab-state={state.id}
    >
      <h1>Controlled public security target</h1>
      <p>This page contains only deterministic synthetic fixtures.</p>

      <form action="/not-accepted" method={state.formMethod} data-lab-inert="true">
        <label htmlFor="lab-password">Synthetic password field</label>
        <input id="lab-password" type="password" autoComplete="off" disabled />
        <button type="button" disabled>Submission disabled</button>
      </form>

      <img
        alt=""
        data-lab-mixed-content="true"
        height="1"
        loading="lazy"
        src={state.mixedContentUrl}
        width="1"
      />
      <LabClient />
      <Script nonce={nonce} src="/lab-resource.js" strategy="afterInteractive" />
    </main>
  );
}
