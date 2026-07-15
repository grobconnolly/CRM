# Putting the Finlete CRM online (Railway, ~$5/month)

The app is already cloud-ready: it has a password login, runs on any port, and
keeps its data on a persistent volume. You only need to do the account signup;
everything else is copy-paste (or ask Claude to run the commands with you).

## One-time setup

**1. Create a Railway account** — https://railway.com → "Login with GitHub"
(create a free GitHub account first if you don't have one). Add a payment
method under Account → Billing (the Hobby plan is $5/month).

**2. Install the Railway CLI** (in Terminal):

    brew install railway

**3. Deploy** (from this folder):

    cd ~/Desktop/CRM
    railway login
    railway init          # create a new project, name it "finlete-crm"
    railway up            # builds the Dockerfile and deploys

**4. In the Railway dashboard** (railway.com → your project → the service):

- **Variables tab** → add `CRM_PASSWORD` = a strong password you share only
  with your co-founder (use a password manager to generate one).
- **Settings → Volumes** → Add Volume, mount path `/data`
  (this is what makes your data survive restarts and redeploys).
- **Settings → Networking** → Generate Domain. That URL is your CRM.

**5. Open the URL, enter the password, done.** Your current data ships with
the deploy, and ranks keep auto-updating weekly in the cloud — even with your
Mac off.

## Day-to-day

- Send the URL + password to your co-founder. You each stay logged in for
  90 days per browser.
- Your local copy (Start CRM.command) still works and keeps its own data —
  treat the cloud one as the real CRM once you switch.
- To update the app after Claude changes the code: `railway up` again.
  Data is safe on the volume.

## Security notes

- Everything is served over HTTPS (Railway handles the certificate).
- Nothing is accessible without the password; wrong guesses are rate-limited.
- If the password ever leaks, change `CRM_PASSWORD` in the Variables tab —
  that instantly logs everyone out everywhere.
