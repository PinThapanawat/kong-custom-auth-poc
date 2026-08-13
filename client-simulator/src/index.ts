import { ensureDeviceIdentity, acquireSession, loadSession, callBffApi } from "./pdsClient";
import { API_IDS } from "./apiRegistry";

const PDS_BASE_URL = process.env.PDS_BASE_URL ?? "http://kong:8000";

const DEMO_USERS: Record<string, string> = {
  "demo-user": "demo-pass",
  "admin-user": "admin-pass"
};

function printResult(label: string, result: { status: number; body: unknown }) {
  console.log(`\n${label} -> HTTP ${result.status}: ${JSON.stringify(result.body, null, 2)}\n`);
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);

  if (command === "enroll") {
    const { identity } = await ensureDeviceIdentity(PDS_BASE_URL);
    console.log(`Device enrolled: ${identity.deviceId}`);
    return;
  }

  if (command === "login") {
    const [username] = rest;
    if (!username || !DEMO_USERS[username]) {
      console.error(`Usage: client-simulator login <${Object.keys(DEMO_USERS).join("|")}>`);
      process.exit(1);
    }
    const { identity, privateKey } = await ensureDeviceIdentity(PDS_BASE_URL);
    console.error(`Acquiring session as ${username} (Category 1: Session Acquiring API)...`);
    const session = await acquireSession(PDS_BASE_URL, identity, privateKey, username, DEMO_USERS[username]);
    console.log(`Session acquired. sessionJwt: ${session.sessionJwt.slice(0, 40)}...`);
    return;
  }

  if (command === "accounts") {
    const { privateKey } = await ensureDeviceIdentity(PDS_BASE_URL);
    const session = loadSession();
    const result = await callBffApi(PDS_BASE_URL, privateKey, session, "GET", "/accounts", API_IDS.ACCOUNTS_LIST);
    printResult("GET /accounts", result);
    return;
  }

  if (command === "transfer" || command === "transfer-tamper") {
    const amount = Number(rest[0] ?? 100);
    const { privateKey } = await ensureDeviceIdentity(PDS_BASE_URL);
    const session = loadSession();
    const result = await callBffApi(
      PDS_BASE_URL,
      privateKey,
      session,
      "POST",
      "/accounts/transfer",
      API_IDS.ACCOUNTS_TRANSFER,
      { to: "ACC-77002", amount },
      command === "transfer-tamper"
    );
    printResult("POST /accounts/transfer", result);
    return;
  }

  console.error("Usage: client-simulator <enroll|login|accounts|transfer|transfer-tamper> [args]");
  console.error(`  enroll                          Generate/persist a device keypair and enroll it with the PDS`);
  console.error(`  login <${Object.keys(DEMO_USERS).join("|")}>       Category 1: acquire a session + SEK`);
  console.error(`  accounts                        Category 2: GET /accounts through the PDS`);
  console.error(`  transfer [amount]                Category 2: POST /accounts/transfer through the PDS`);
  console.error(`  transfer-tamper [amount]         Same, but flips a ciphertext byte to prove tamper detection`);
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
