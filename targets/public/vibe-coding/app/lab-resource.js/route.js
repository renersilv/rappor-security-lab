import { getState, renderPublicResource } from "../../lib/states.mjs";

export const dynamic = "force-dynamic";

export async function GET() {
  return new Response(renderPublicResource(getState()), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/javascript; charset=utf-8",
    },
  });
}
