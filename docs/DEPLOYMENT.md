# Deploying AstraSec

## Can this go on Vercel?

**The dashboard, yes. The backend, no.** That is not a preference — it is four
hard blockers, measured on this project:

| Blocker | Measured | Vercel limit |
|---|---|---|
| Function size | 318 MB deps (scipy 112, pandas 71, sklearn 47, numpy 43) + 54 MB model = **372 MB** | 250 MB uncompressed |
| Cold start | **7 s** to import the stack and load the models | Every scale-to-zero invocation pays it |
| Process state | Modules 1, 4 and 5 keep per-tenant baselines, token buckets, threat streaks, quarantine and immune memory **in process** | Functions are ephemeral — state resets every invocation |
| WebSocket | `/ws/feed` holds a persistent connection | Not supported on serverless functions |
| Filesystem | SQLite audit trail writes to disk | Read-only except ephemeral `/tmp` |

The size and cold-start problems could be engineered around. **The state problem
cannot.** AstraSec's entire argument is that it is *not* a stateless classifier:
behavioural baselines learn per tenant, quarantine accumulates across requests,
immune memory improves with exposure. Run it on ephemeral functions and Modules
1, 4 and 5 are reduced to no-ops while still appearing to work — the worst
possible failure mode for a security tool, and an obvious question at a viva.

So: put the dashboard on Vercel and the backend on something that keeps a
process alive.

---

## Option A — Everything on one host (simplest)

One container, everything works: WebSocket, immune memory, audit trail. This is
what to pick unless you specifically need a `.vercel.app` URL.

### Hugging Face Spaces (free, no card)

```bash
pip install huggingface_hub
huggingface-cli login

huggingface-cli repo create astrasec --type space --space_sdk docker
git clone https://huggingface.co/spaces/<your-username>/astrasec hf-astrasec
cd hf-astrasec

# copy the project in, using the Spaces Dockerfile (port 7860)
cp -r ../astrasec/{backend,frontend,scripts,docs} .
cp ../astrasec/docker/Dockerfile.hfspace ./Dockerfile

git add -A && git commit -m "AstraSec" && git push
```

The Space builds and trains (~15 min), then serves at
`https://<username>-astrasec.hf.space`. Free, warm, no sleep on the CPU tier.

### Render

`render.yaml` is already in the repo. Push to GitHub, then Render →
**New → Blueprint** → pick the repo. Set `ASTRASEC_CORS_ORIGINS` to your own
domain.

The free tier sleeps after 15 minutes idle and takes ~40 s to wake; immune
memory and tenant baselines reset on sleep, like any restart. For a live demo,
use Starter (~$7/mo) or just wake it a minute before you present.

### Railway / Fly.io

Both consume the existing `Dockerfile` unchanged:

```bash
railway up                      # or
fly launch --dockerfile Dockerfile
```

---

## Option B — Dashboard on Vercel, backend on a container host

Use this if you want the Vercel URL. The dashboard already supports it: the API
base and the WebSocket both follow `VITE_API_BASE`.

### 1. Deploy the backend first

Any host from Option A. Note the URL, e.g.
`https://astrasec-api.onrender.com`.

### 2. Deploy the dashboard to Vercel

```bash
cd frontend
npx vercel
```

Vercel will detect Vite. `frontend/vercel.json` is already committed with the
SPA rewrite and asset caching.

**Set the project root to `frontend/`** — in the Vercel dashboard under
*Settings → General → Root Directory*. If you point Vercel at the repo root it
will try to build the Python backend and fail.

### 3. Point the dashboard at the API

In Vercel → *Settings → Environment Variables*:

```
VITE_API_BASE = https://astrasec-api.onrender.com
```

Then **redeploy** — Vite bakes env vars in at build time, so a variable added
after a build has no effect until the next one.

### 4. Allow the dashboard's origin on the backend

On the backend host:

```
ASTRASEC_ENVIRONMENT  = production
ASTRASEC_CORS_ORIGINS = ["https://your-project.vercel.app"]
```

In production the CORS allow-list is *exactly* this value. In development every
origin is allowed so local work needs no configuration, but a deployed security
control should not answer `Access-Control-Allow-Origin: *`.

Include every origin you will actually use — Vercel preview deployments get
their own subdomains:

```
ASTRASEC_CORS_ORIGINS = ["https://astrasec.vercel.app","https://astrasec-git-main-you.vercel.app"]
```

### 5. Verify

```bash
curl https://astrasec-api.onrender.com/api/health
```

Expect `"models_loaded": true`. Then open the Vercel URL — the sidebar should
show **Live feed connected**. If it shows *disconnected*, the WebSocket is being
blocked: check that `VITE_API_BASE` uses `https://` (the client rewrites it to
`wss://`) and that your host supports WebSocket upgrades.

---

## What breaks where

| Feature | One host | Vercel + container | Vercel alone |
|---|---|---|---|
| Threat prediction (Module 3) | works | works | would work |
| Behaviour baselines (Module 1) | works | works | **resets every request** |
| Rate limit / quarantine (Module 4) | works | works | **never triggers** |
| Immune memory (Module 5) | works | works | **never recalls** |
| Live feed (WebSocket) | works | works | **unsupported** |
| Audit trail (SQLite) | works | works | **lost** |

---

## Deployment checklist

- [ ] `ASTRASEC_ENVIRONMENT=production`
- [ ] `ASTRASEC_CORS_ORIGINS` lists every dashboard origin
- [ ] Persistent disk mounted at `/app/artifacts` (models, memory, audit log)
- [ ] Health check pointed at `/api/health`
- [ ] At least 2 GB RAM — training peaks around 1.5 GB
- [ ] `VITE_API_BASE` set in Vercel **and** redeployed afterwards

---

## Two things to know before demo day

**Training happens in the Docker build**, so the first deploy takes 15–20
minutes. Build once, well before you present.

**Free tiers sleep.** Render free and similar spin down after ~15 minutes idle.
The first request then waits ~40 s *and* starts from empty immune memory, so the
dashboard opens with zeros. Hit the URL a couple of minutes before presenting,
then click **Simulate 250 requests** to populate it.
