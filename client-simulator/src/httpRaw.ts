import * as http from "node:http";
import * as https from "node:https";
import { URL } from "node:url";

// Node's global `fetch` refuses to send a body on GET/HEAD requests (per
// the Fetch spec), but Category 2's "list accounts" is a GET that still
// needs to carry a signed+encrypted envelope in its body (PDF pp.4-5 — the
// spec doesn't special-case GET). Node's core `http`/`https` modules have
// no such restriction, and Express on the PDS side reads whatever bytes are
// present regardless of method, so this is the one place this client drops
// down to the raw transport instead of `fetch`.

export interface RawHttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

export function rawHttpRequest(
  urlString: string,
  method: string,
  headers: Record<string, string>,
  body?: Buffer
): Promise<RawHttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const transport = url.protocol === "https:" ? https : http;
    const req = transport.request(
      url,
      {
        method,
        headers: {
          ...headers,
          ...(body ? { "Content-Length": String(body.length) } : {})
        }
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
      }
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
