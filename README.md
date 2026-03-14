# rupesh-bodke-web

Rupesh Bodke's personal portfolio website — a single-page, responsive site built with pure HTML & CSS.

---

## Deploying to GitHub Pages

Follow these steps to make your portfolio live at **https://rupesh-BODKE.github.io/rupesh-bodke-web/**.

> **Want it at `rupesh-BODKE.github.io` (root)?** Rename this repository to
> `rupesh-BODKE.github.io` in **Settings → General → Repository name**, then
> use that name wherever you see `rupesh-bodke-web` below.

### Prerequisites

- A [GitHub](https://github.com) account
- [Git](https://git-scm.com/downloads) installed on your machine

### Step 1 — Clone the repository

```bash
git clone https://github.com/rupesh-BODKE/rupesh-bodke-web.git
cd rupesh-bodke-web
```

### Step 2 — Personalise the site

Open `index.html` in your editor and replace every `<!-- PLACEHOLDER -->` section with your own information (photo, bio, skills, experience, projects, and contact details). Preview locally by opening the file in a browser.

### Step 3 — Commit your changes

```bash
git add .
git commit -m "Personalise portfolio content"
```

### Step 4 — Push to GitHub

```bash
git push origin main
```

### Step 5 — Enable GitHub Pages

1. Go to your repository on GitHub: **https://github.com/rupesh-BODKE/rupesh-bodke-web**
2. Click **Settings** (top menu bar).
3. In the left sidebar click **Pages**.
4. Under **Build and deployment → Source**, select **GitHub Actions**.
5. The existing workflow (`.github/workflows/static.yml`) will automatically deploy on every push to `main`.

### Step 6 — Verify the deployment

After a push to `main`, open the **Actions** tab in your repository to watch the workflow run. Once it succeeds, your site will be live at:

```
https://rupesh-BODKE.github.io/rupesh-bodke-web/
```

### Making further changes

Every time you edit files and push to `main`, the site is automatically redeployed:

```bash
# edit files, then…
git add .
git commit -m "Update portfolio"
git push origin main
```

You can also trigger a manual deploy from the **Actions** tab → **Deploy static content to Pages** → **Run workflow**.

---

## How the deployment works

This repository includes a GitHub Actions workflow at `.github/workflows/static.yml` that:

1. Checks out the repository.
2. Configures GitHub Pages.
3. Uploads the entire repository as a Pages artifact.
4. Deploys the artifact to GitHub Pages.

The workflow runs automatically on every push to the `main` branch and can also be triggered manually via `workflow_dispatch`.

---

## Local development

No build step is required — just open `index.html` in any browser:

```bash
# macOS
open index.html

# Linux
xdg-open index.html

# Windows
start index.html
```

---

## License

© 2026 Rupesh Bodke