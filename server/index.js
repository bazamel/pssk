import {
  signup,
  checkSignup,
  generateLogin,
  checkLogin,
} from "../packages/server/index.js";

import crypto from "node:crypto";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";

const app = new Hono();

app.use(cors("*"));

let USERS = new Map();

function getOrCreateUser(email) {
  if (!USERS.has(email)) {
    USERS.set(email, {
      id: crypto.randomBytes(32),
      email: email,
      credentials: [],
    });
  }
  return USERS.get(email);
}

app.post("/signup", async (c) => {
  const { email } = await c.req.json();

  let user = getOrCreateUser(email);

  const signupOptions = await signup(user);

  user.currentChallenge = signupOptions.challenge;

  return c.json({ ok: true, options: signupOptions });
});
app.post("/check-signup", async (c) => {
  const { email, credential } = await c.req.json();

  let user = USERS.get(email);

  const res = await checkSignup(user, credential);

  if (!res.ok) throw new Error("bad credential");

  user.credentials.push(res.credential);
  delete user.currentChallenge;

  return c.json({ ok: true });
});

app.post("/login", async (c) => {
  const { email } = await c.req.json();

  const user = USERS.get(email);

  let authOptions = await generateLogin(user);

  user.currentLoginChallenge = authOptions.challenge;

  return c.json({ ok: true, options: authOptions });
});

app.post("/check-login", async (c) => {
  const { email, credential } = await c.req.json();

  let user = USERS.get(email);

  const res = await checkLogin(user, credential);

  if (!res) throw new Error("invalid login");

  delete user.currentLoginChallenge;

  return c.json({ ok: true });
});

serve(app);
