import express from "express";

const app = express();
const port = Number(process.env.PORT ?? 8080);

app.use(express.json());

type AuthResponse = {
  authenticated: boolean;
  user?: {
    id: string;
    client_id: string;
  };
  authorization?: {
    roles: string[];
    scopes: string[];
  };
};

const USERS: Record<string, AuthResponse> = {
  "demo-token": {
    authenticated: true,
    user: {
      id: "user-123",
      client_id: "demo-client"
    },
    authorization: {
      roles: ["customer"],
      scopes: ["account.read"]
    }
  },
  "admin-token": {
    authenticated: true,
    user: {
      id: "admin-001",
      client_id: "admin-client"
    },
    authorization: {
      roles: ["admin"],
      scopes: ["account.read", "account.write"]
    }
  }
};

app.get("/health", (_req, res) => {
  res.json({ status: "UP" });
});

app.post("/validate", (req, res) => {
  const caller = req.header("X-Auth-Caller");

  // Only Kong should be allowed to call this endpoint.
  // In production, enforce this with mTLS/network policy as well.
  if (caller !== "kong") {
    return res.status(403).json({
      authenticated: false,
      message: "Caller is not trusted"
    });
  }

  const token = req.body?.token;

  if (typeof token !== "string" || token.length === 0) {
    return res.status(401).json({
      authenticated: false
    });
  }

  const result = USERS[token];

  if (!result) {
    return res.status(401).json({
      authenticated: false
    });
  }

  return res.status(200).json(result);
});

app.listen(port, () => {
  console.log(`Custom Auth Service listening on ${port}`);
});
