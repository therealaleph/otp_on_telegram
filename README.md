# Telegram OTP Bot on Cloudflare Workers

This project provides a script to deploy a secure Telegram bot using Cloudflare Workers and KV storage. The bot allows you to retrieve Time-based One-Time Password (TOTP) codes for your online accounts directly within Telegram after authenticating with a password.

It reads your `otpauth://` URLs (exported from authenticator apps like Google Authenticator) during the setup process and stores necessary configurations securely using Wrangler secrets and KV namespaces.

**Disclaimer:** This project handles sensitive data (your OTP secrets). While it uses Cloudflare's infrastructure and Wrangler's secret management, ensure you understand the security implications and secure your Cloudflare account and Telegram bot token appropriately.

## Features

* **Telegram Bot Interface:** Access your OTP codes via simple Telegram commands.
* **Password Protection:** Bot access is secured by a password you define during setup.
* **Session Management:** Uses Cloudflare KV for temporary user sessions with attempt limits and timeouts.
* **Dynamic OTP Generation:** Supports standard TOTP generation (SHA1/SHA256/SHA512, 6-8 digits, custom periods) based on `otpauth://` URLs.
* **Automated Deployment:** A bash script handles Cloudflare resource creation (Worker, KV), secret management, deployment, and Telegram webhook setup.
* **No Hardcoded Secrets:** Your Bot Token, access password, and OTP URLs are not stored in the repository code.

## Prerequisites

Before you begin, ensure you have the following:

1.  **A Cloudflare Account:** Required for deploying Workers and using KV storage. [Sign up here](https://dash.cloudflare.com/sign-up).
2.  **Node.js and npm:** Required to install the Wrangler CLI. Download Node.js (which includes npm) from [nodejs.org](https://nodejs.org/) (LTS version is recommended). Verify installation:
    ```bash
    node -v
    npm -v
    ```
3.  **Wrangler CLI:** The command-line tool for managing Cloudflare Workers. Install it globally via npm:
    ```bash
    npm install -g wrangler
    ```
4.  **Wrangler Login:** You **must** be logged into your Cloudflare account via Wrangler for the script to work. Run:
    ```bash
    wrangler login
    ```
    Follow the instructions to authorize Wrangler with your Cloudflare account.
5.  **A Telegram Bot Token:** Create a bot using Telegram's [BotFather](https://t.me/botfather). Follow the instructions BotFather gives you and **save the HTTP API token** securely. You will need it during the script execution.
6.  **Your `otpauth://` URLs:** Export your 2FA accounts from your authenticator app (e.g., Google Authenticator has an export feature). You need the raw `otpauth://...` URLs. Have these ready to copy and paste during the setup.

## Installation and Setup

1.  **Clone the Repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```
2.  **Ensure Prerequisites:** Double-check that Node.js, npm, and Wrangler are installed and that you are logged in via `wrangler login`.
3.  **Make the Deployment Script Executable:**
    This command grants the script permission to run.
    ```bash
    chmod +x deploy_otp_bot.sh
    ```
4.  **Run the Deployment Script:**
    ```bash
    ./deploy_otp_bot.sh
    ```
5.  **Follow the Prompts:** The script will interactively ask you for:
    * A unique name for your Cloudflare Worker (e.g., `my-secure-otp-bot`).
    * A name for the Cloudflare KV Namespace (e.g., `OTP_BOT_SESSIONS`).
    * Your Telegram Bot Token (paste the token you got from BotFather). Input will be hidden.
    * An access password for the bot (choose a strong, unique password). Input will be hidden.
6.  **Add OTP URLs:**
    * The script will create a file named `auth_list.txt` in the current directory and pause.
    * Open `auth_list.txt` with a text editor.
    * Paste **all** your `otpauth://...` URLs into this file, **one URL per line**.
    * Save the `auth_list.txt` file and close the editor.
    * Go back to the terminal and type `go`, then press Enter.
7.  **Automatic Deployment:** The script will now:
    * Read the URLs from `auth_list.txt`.
    * Generate the `src/index.js` Worker code with your URLs embedded.
    * Create or reuse the specified KV Namespace.
    * Create the `wrangler.toml` configuration file.
    * Securely upload your Bot Token and Access Password as secrets using `wrangler secret put`.
    * Deploy the Worker script to Cloudflare.
    * Attempt to automatically set the Telegram webhook to point to your new Worker URL.

## Usage

Once deployed successfully:

1.  Open Telegram and find the bot you created.
2.  Send the `/start` command.
3.  The bot will ask for the access password you set during installation.
4.  Enter the correct password.
5.  The bot will list your configured OTP accounts with numbers.
6.  Reply with the number corresponding to the account you need an OTP for.
7.  The bot will provide the current OTP code and the session will end.
8.  To get another code, you need to `/start` again.

## Security Considerations

* **Strong Password:** Use a strong, unique password for bot access.
* **Bot Token:** Keep your Telegram Bot Token confidential. Do not commit it to Git or share it publicly. The script uses Wrangler secrets for this.
* **Cloudflare Account Security:** Secure your Cloudflare account with a strong password and enable Two-Factor Authentication (2FA). Anyone with access to your Cloudflare account could potentially access the KV namespace or modify the worker.
* **KV Storage:** While access is controlled, be aware that data in Cloudflare KV is encrypted at rest by Cloudflare, but accessible via the Cloudflare dashboard/API if your account is compromised.
* **`auth_list.txt`:** This file contains your sensitive `otpauth://` secrets *during setup*. The script **does not automatically delete this file** after execution. Consider deleting `auth_list.txt` securely after a successful deployment, or store the project in a secure location.
* **Webhook Security:** The worker URL is public. The security relies on the password check within the worker code and Telegram's secure handling of updates.

## Troubleshooting

* **Wrangler Errors:** Ensure Wrangler is up-to-date (`npm install -g wrangler`) and you are logged in (`wrangler login`). Check the error messages provided by Wrangler during deployment.
* **Bot Not Responding:**
    * Verify the webhook was set correctly. You can check using `curl https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getWebhookInfo`.
    * Check the worker logs in near-real-time using `wrangler tail <YOUR_WORKER_NAME>`. This often shows errors happening within the worker code.
* **Incorrect OTPs:** Double-check the `otpauth://` URLs you pasted into `auth_list.txt` for any typos or corruption. Ensure your server/computer time is synchronized accurately.

## Platform Compatibility

This deployment script is designed for Linux and macOS environments due to its use of bash and standard Unix utilities (`chmod`, `touch`, `sed`, `awk`, `curl`, etc.). Windows users may use the Windows Subsystem for Linux (WSL) to run the script.
