
export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const origin = process.env.APP_ORIGIN;

  if (!origin || req.headers.origin !== origin) {
    return res.status(403).json({
      error: "Invalid origin"
    });
  }

  const token = req.body?.token;

  if (typeof token !== "string" || !token || token.length > 2048) {
    return res.status(400).json({
      error: "Invalid token"
    });
  }

  try {
    const form = new FormData();
    form.append("secret", process.env.TURNSTILE_SECRET_KEY);
    form.append("response", token);

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: form }
    );

    if (!response.ok) {
      return res.status(503).json({
        error: "Verification unavailable"
      });
    }

    const result = await response.json();
    const hostname = new URL(origin).hostname;

    if (
      result.success !== true ||
      result.hostname !== hostname
    ) {
      return res.status(403).json({
        error: "Verification failed"
      });
    }

    return res.status(200).json({ verified: true });
  } catch {
    return res.status(503).json({
      error: "Verification unavailable"
    });
  }
}
