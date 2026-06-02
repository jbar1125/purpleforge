# Splunk Setup Guide for PurpleForge

Do these steps once before running `setup_verify.py`.
Splunk Enterprise runs at http://localhost:8000 by default.

---

## Step 1: Find Your Admin Username

When you installed Splunk Enterprise, it asked you to create an admin account.
- Your local Splunk admin username is likely `admin` (NOT your splunk.com email)
- If you forgot your password, reset it via:
  `$SPLUNK_HOME\bin\splunk edit user admin -password NEWPASS -auth admin:OLDPASS`
  Default SPLUNK_HOME on Windows: `C:\Program Files\Splunk`

---

## Step 2: Enable the HTTP Event Collector (HEC)

1. Log in at http://localhost:8000
2. Go to **Settings → Data Inputs → HTTP Event Collector**
3. Click **Global Settings** (top right). Set:
   - Enable SSL: **Yes** (keep default)
   - HTTP Port Number: **8088**
   - Click **Save**
4. Click **New Token**:
   - Name: `purpleforge`
   - Source type: leave blank (we set it per-event)
   - Index: leave as default (we set it per-event)
   - Click through to finish
5. Copy the **Token Value** — you'll paste this into `config.yaml` as `hec_token`

---

## Step 3: Create the Indexes

1. Go to **Settings → Indexes → New Index**
2. Create index named: `arena_baseline`
   - Max Size: 500 MB (plenty)
   - Click **Save**
3. Create index named: `arena_attacks`
   - Max Size: 500 MB
   - Click **Save**

---

## Step 4: Enable the REST API

The REST API (port 8089) is enabled by default on Splunk Enterprise.
Verify it's running: open https://localhost:8089/services in your browser.
You'll get a certificate warning — accept it (self-signed cert is normal).

---

## Step 5: Fill in config.yaml

```bash
cd C:\Users\Jacob Barzideh\splunk-hackathon\purpleforge
copy config.example.yaml config.yaml
```

Open `config.yaml` and fill in:
```yaml
splunk:
  username: admin                    # your local Splunk admin username
  password: "your_splunk_password"   # your local Splunk admin password
  hec_token: "paste_token_here"      # from Step 2
```

---

## Step 6: Install the Splunk MCP Server (for MCP prize)

1. Go to https://splunkbase.splunk.com and search "MCP Server"
2. Download and install the app
3. Follow its setup instructions — it typically runs on port 3000
4. `setup_verify.py` will confirm it's reachable

---

## Step 7: Get a Free LLM API Key (Gemini)

1. Go to https://aistudio.google.com/app/apikey
2. Sign in with your Google account
3. Click **Create API key**
4. Copy the key into `config.yaml` under `llm.gemini.api_key`

Free tier: 15 requests/minute — more than enough for the arena.

---

## Step 8: Run the Setup Verification

```bash
cd C:\Users\Jacob Barzideh\splunk-hackathon\purpleforge
pip install -r requirements.txt
python setup_verify.py
```

All critical checks should pass before you run the full arena.

---

## Step 9: Run PurpleForge

```bash
python orchestrator/main.py
```

The terminal will show round-by-round results. Open the Splunk dashboard to see
the live heatmap during the run.

### To load the dashboard in Splunk:
1. Go to **Search & Reporting** in Splunk
2. Click **Dashboards → Create New Dashboard**
3. Click the **Source** button (top right of editor)
4. Paste the contents of `dashboard/purpleforge_dashboard.xml`
5. Click **Save**
