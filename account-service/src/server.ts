import express from "express";

const app = express();
const port = Number(process.env.PORT ?? 8080);

app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "UP" });
});

app.get("/accounts", (req, res) => {
  const authenticated = req.header("X-Auth-Authenticated");
  const userId = req.header("X-User-ID");
  const clientId = req.header("X-Client-ID");
  const scopes = (req.header("X-User-Scopes") ?? "")
    .split(",")
    .filter(Boolean);

  if (authenticated !== "true" || !userId) {
    return res.status(401).json({
      message: "Missing trusted authentication context"
    });
  }

  if (!scopes.includes("account.read")) {
    return res.status(403).json({
      message: "Missing account.read permission"
    });
  }

  // Demo business authorization.
  return res.json({
    user: {
      id: userId,
      client_id: clientId
    },
    accounts: [
      {
        id: "ACC-10001",
        type: "SAVINGS",
        currency: "THB",
        balance: 125000.50
      }
    ]
  });
});

app.post("/accounts/transfer", (req, res) => {
  const authenticated = req.header("X-Auth-Authenticated");
  const userId = req.header("X-User-ID");
  const scopes = (req.header("X-User-Scopes") ?? "")
    .split(",")
    .filter(Boolean);

  if (authenticated !== "true" || !userId) {
    return res.status(401).json({
      message: "Missing trusted authentication context"
    });
  }

  if (!scopes.includes("account.write")) {
    return res.status(403).json({
      message: "Missing account.write permission"
    });
  }

  const { to, amount } = req.body ?? {};

  if (typeof to !== "string" || typeof amount !== "number") {
    return res.status(400).json({
      message: "Expected { to: string, amount: number }"
    });
  }

  // Demo business logic.
  return res.json({
    status: "COMPLETED",
    from: "ACC-10001",
    to,
    amount,
    currency: "THB"
  });
});

app.listen(port, () => {
  console.log(`Account Service listening on ${port}`);
});
