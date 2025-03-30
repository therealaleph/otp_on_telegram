#!/bin/bash

function check_command {
  if ! command -v $1 &> /dev/null; then
    echo "Error: $1 command not found. Please install $1."
    exit 1
  fi
}

function fail {
  echo "Error: $1" >&2
  exit 1
}

check_command wrangler
check_command curl
check_command jq
check_command grep
check_command sed
check_command awk
check_command cut
check_command head
check_command touch
check_command rm

echo "Checking Wrangler version..."
WRANGLER_VERSION_OUTPUT=$(wrangler --version) || fail "Could not get Wrangler version. Is it installed and in PATH?"
WRANGLER_VERSION_NUMBER=$(echo "$WRANGLER_VERSION_OUTPUT" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
WRANGLER_MAJOR_VERSION=$(echo "$WRANGLER_VERSION_NUMBER" | cut -d. -f1)

echo "Detected Wrangler version: $WRANGLER_VERSION_NUMBER (Major: $WRANGLER_MAJOR_VERSION)"

if [[ -z "$WRANGLER_MAJOR_VERSION" ]] || (( WRANGLER_MAJOR_VERSION < 3 )); then
  fail "This script requires Wrangler version 3 or higher. Please update Wrangler (npm install -g wrangler)."
fi
echo "Wrangler version check passed."

echo ""
echo "--- Configuration Input ---"
read -p "Enter a unique name for your Cloudflare Worker: " WORKER_NAME
read -p "Enter the name for the Cloudflare KV Namespace (e.g., OTP_BOT_SESSIONS): " KV_NAMESPACE_NAME
read -sp "Enter your Telegram Bot Token: " BOT_TOKEN
echo ""
read -sp "Enter the password users will need to access OTPs: " OTP_PASSWORD
echo ""
echo "--------------------------"

if [[ -z "$WORKER_NAME" || -z "$KV_NAMESPACE_NAME" || -z "$BOT_TOKEN" || -z "$OTP_PASSWORD" ]]; then
    fail "One or more configuration values were left empty. Aborting."
fi

echo ""
echo "--- OTP URL Input ---"
AUTH_LIST_FILE="auth_list.txt"
touch "$AUTH_LIST_FILE" || fail "Could not create $AUTH_LIST_FILE"
echo "1. An empty file named '$AUTH_LIST_FILE' has been created in the current directory."
echo "2. Please open this file in a text editor."
echo "3. Paste ALL your 'otpauth://...' URLs into this file."
echo "4. Each URL must be on a new line."
echo "5. Save the file and close the editor."

user_go=""
while [[ "$user_go" != "go" ]]; do
    read -p "Type 'go' and press Enter when you have saved the URLs in $AUTH_LIST_FILE: " user_go
done

echo "Reading OTP URLs from $AUTH_LIST_FILE..."

if [ ! -s "$AUTH_LIST_FILE" ]; then
    rm "$AUTH_LIST_FILE" # Clean up empty file
    fail "$AUTH_LIST_FILE is empty. Please provide at least one otpauth:// URL."
fi

# Process URLs: Escape single quotes, wrap in single quotes, add commas
# 1. Escape existing single quotes (') with ('\') within the URL itself. Needs careful escaping for sed within bash.
# 2. Wrap each line in single quotes ('line').
# 3. Add a comma at the end of each line.
# 4. Store in a variable.
# 5. Remove the trailing comma from the last line.
FORMATTED_URLS=$(sed -e "s/'/'\\\\''/g" -e "s/.*/'&',/" "$AUTH_LIST_FILE")
# Remove the trailing comma from the very last line
FORMATTED_URLS=$(echo "$FORMATTED_URLS" | sed '$ s/,$//')

# Optional: Clean up the auth_list.txt file now if you don't want it lingering
# read -p "Do you want to delete the $AUTH_LIST_FILE file now? (y/N): " delete_file
# if [[ "$delete_file" =~ ^[Yy]$ ]]; then
#     rm "$AUTH_LIST_FILE" || echo "Warning: Could not delete $AUTH_LIST_FILE"
#     echo "$AUTH_LIST_FILE deleted."
# fi
# --- Leaving the file might be useful for debugging, so commented out by default ---

echo "OTP URLs processed."
echo "---------------------"

echo "Creating project structure..."
mkdir -p src || fail "Could not create src directory."

echo "Creating wrangler.toml..."
COMPAT_DATE=$(date +%Y-%m-%d)
cat << EOF > wrangler.toml
name = "$WORKER_NAME"
main = "src/index.js"
compatibility_date = "$COMPAT_DATE"

[vars]

EOF
echo "wrangler.toml created."

echo "Creating src/index.js..."

# Write the first part of the JS file
cat << 'EOF' > src/index.js
const otpUrls = [
EOF

# Append the dynamically generated URLs
echo "$FORMATTED_URLS" >> src/index.js

# Write the rest of the JS file
cat << 'EOF' >> src/index.js
];

const SESSION_TTL = 5 * 60;

function parseOtpUrl(otpUrl) {
    try {
        const url = new URL(otpUrl);
        if (url.protocol !== 'otpauth:') return null;

        const secret = url.searchParams.get('secret');
        if (!secret) return null;

        const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
        const digits = parseInt(url.searchParams.get('digits') || '6', 10);
        const period = parseInt(url.searchParams.get('period') || '30', 10);
        const issuer = url.searchParams.get('issuer');

        let label = decodeURIComponent(url.pathname || '').replace(/^\//, '');
        if (label.startsWith('totp/')) {
           label = label.substring(5);
        }

        let issueName = issuer;
        if (!issueName) {
            const labelParts = label.split(':');
            if (labelParts.length > 1) {
                issueName = labelParts[0];
                label = labelParts.slice(1).join(':');
            } else if (label.includes('@')) {
                issueName = label.split('@')[1];
            }
        }
        if (!issueName && url.hostname && url.hostname !== 'totp') {
            issueName = url.hostname;
        } else if (!issueName) {
            const labelMatch = label.match(/^([^\(@:]+)/);
            if (labelMatch) issueName = labelMatch[1].trim();
        }

        if (issueName && issueName.includes('.')) {
             const domainParts = issueName.split('.');
             if (domainParts.length > 1) {
                 issueName = domainParts[0];
             }
        }


        return {
            secret,
            algorithm: algorithm === 'SHA1' ? 'SHA-1' : (algorithm === 'SHA256' ? 'SHA-256' : (algorithm === 'SHA512' ? 'SHA-512' : 'SHA-1')),
            digits,
            period,
            label: label || 'Unknown Label',
            issueName: issueName || 'Unknown Issuer',
        };
    } catch (e) {
        console.error(`Error parsing OTP URL "${otpUrl}": ${e}`);
        return null;
    }
}

function base32Decode(base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let value = 0;

    base32 = base32.replace(/=+$/, '').toUpperCase();

    for (let i = 0; i < base32.length; i++) {
        value = base32Chars.indexOf(base32.charAt(i));
        if (value === -1) throw new Error('Invalid Base32 character found');
        bits += value.toString(2).padStart(5, '0');
    }

    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }
    return bytes;
}

async function generateOtp(secret, algorithm, digits, period) {
    try {
        const key = base32Decode(secret);
        const epoch = Math.floor(Date.now() / 1000);
        const timeStep = Math.floor(epoch / period);

        const timeBytes = new ArrayBuffer(8);
        const timeView = new DataView(timeBytes);
        const MAX_UINT32 = 0xFFFFFFFF;
        const high = Math.floor(timeStep / (MAX_UINT32 + 1));
        const low = timeStep % (MAX_UINT32 + 1);
        timeView.setUint32(0, high, false);
        timeView.setUint32(4, low, false);

        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'HMAC', hash: algorithm },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            timeBytes
        );

        const hash = new Uint8Array(signature);
        const offset = hash[hash.length - 1] & 0x0f;

        const binary = ((hash[offset] & 0x7f) << 24) |
                       ((hash[offset + 1] & 0xff) << 16) |
                       ((hash[offset + 2] & 0xff) << 8) |
                       (hash[offset + 3] & 0xff);

        const otp = binary % Math.pow(10, digits);

        return otp.toString().padStart(digits, '0');
    } catch (e) {
        console.error(`Error generating OTP: ${e}`);
        throw new Error('Failed to generate OTP');
    }
}


async function sendMessage(chatId, text, env) {
    const apiUrl = `https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`;
    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text: text }),
        });
        if (!response.ok) {
            console.error(`Telegram API error: ${response.status} ${await response.text()}`);
        }
    } catch (error) {
        console.error(`Failed to send message to Telegram: ${error}`);
    }
}

async function showOtpList(chatId, otpData, env) {
    if (!otpData || otpData.length === 0) {
        await sendMessage(chatId, 'No valid OTP configurations found. Check the otpUrls list.', env);
        return;
    }
    const list = otpData
        .map((data, index) => `${index + 1}. ${data.issueName} (${data.label})`)
        .join('\n');
    await sendMessage(chatId, `Select an OTP code by number:\n${list}`, env);
}

let parsedOtpData = null;

export default {
    async fetch(request, env, ctx) {
        if (!env.OTP_BOT_SESSIONS) {
            console.error("KV Namespace 'OTP_BOT_SESSIONS' is not bound correctly. Check wrangler.toml and deployment.");
            return new Response('Internal Server Error: KV Namespace not configured.', { status: 500 });
        }
        if (!env.BOT_TOKEN || !env.OTP_PASSWORD) {
            console.error("Secrets BOT_TOKEN or OTP_PASSWORD are not set via `wrangler secret put`.");
            return new Response("Internal Server Error: Bot secrets not configured.", { status: 500 });
        }

        if (request.method !== 'POST') {
            return new Response('Not Found. This endpoint only accepts POST requests from Telegram.', { status: 404 });
        }

        if (!parsedOtpData) {
             try {
                parsedOtpData = otpUrls.map(parseOtpUrl).filter(Boolean);
                if (parsedOtpData.length === 0 && otpUrls.length > 0) {
                    console.error("Warning: No valid OTP URLs could be parsed from the list provided in the code.");
                } else if (otpUrls.length === 0) {
                     console.error("Warning: The otpUrls list in the code is empty.");
                }
             } catch (parseError) {
                console.error("Critical error during initial OTP URL parsing:", parseError);
                parsedOtpData = [];
             }
        }

        let update;
        try {
            update = await request.json();

            if (!update.message || !update.message.chat || !update.message.from || !update.message.text) {
                console.log('Ignoring update without essential message/chat/from/text info.');
                return new Response('OK', { status: 200 });
            }

            const chatId = update.message.chat.id.toString();
            const userId = update.message.from.id.toString();
            const text = update.message.text;

            if (text === '/start') {
                const initialSession = { state: 'waiting_password', attempts: 0 };
                await env.OTP_BOT_SESSIONS.put(userId, JSON.stringify(initialSession), { expirationTtl: SESSION_TTL });
                await sendMessage(chatId, 'Please enter the password to access your OTP codes.', env);
                return new Response('OK', { status: 200 });
            }

            const sessionString = await env.OTP_BOT_SESSIONS.get(userId);
            if (!sessionString) {
                await sendMessage(chatId, 'Your session has expired or was not started. Please type /start again.', env);
                return new Response('OK', { status: 200 });
            }

            let session;
            try {
                 session = JSON.parse(sessionString);
            } catch (jsonError) {
                console.error(`Failed to parse session JSON for user ${userId}: ${jsonError}. Resetting state.`);
                await env.OTP_BOT_SESSIONS.delete(userId);
                await sendMessage(chatId, 'There was an issue with your session data. Please type /start again.', env);
                return new Response('OK', { status: 200 });
            }


            if (session.state === 'waiting_password') {
                if (text === env.OTP_PASSWORD) {
                    session.state = 'selecting_otp';
                    session.attempts = 0;
                    await env.OTP_BOT_SESSIONS.put(userId, JSON.stringify(session), { expirationTtl: SESSION_TTL });
                    await showOtpList(chatId, parsedOtpData, env);
                } else {
                    session.attempts = (session.attempts || 0) + 1;
                    if (session.attempts >= 3) {
                        await env.OTP_BOT_SESSIONS.delete(userId);
                        await sendMessage(chatId, `Too many incorrect password attempts (${session.attempts}/3). Session closed. Type /start to try again.`, env);
                    } else {
                        await env.OTP_BOT_SESSIONS.put(userId, JSON.stringify(session), { expirationTtl: SESSION_TTL });
                        await sendMessage(chatId, `Incorrect password (${session.attempts}/3 attempts). Please try again.`, env);
                    }
                }
                return new Response('OK', { status: 200 });
            }

            else if (session.state === 'selecting_otp') {
                const selectedIndex = parseInt(text, 10) - 1;

                if (isNaN(selectedIndex) || selectedIndex < 0 || selectedIndex >= parsedOtpData.length) {
                    await sendMessage(chatId, 'Invalid selection number. Please try again.', env);
                    await showOtpList(chatId, parsedOtpData, env);
                    await env.OTP_BOT_SESSIONS.put(userId, JSON.stringify(session), { expirationTtl: SESSION_TTL });

                } else {
                    const selectedOtpData = parsedOtpData[selectedIndex];
                    try {
                        const otp = await generateOtp(
                            selectedOtpData.secret,
                            selectedOtpData.algorithm,
                            selectedOtpData.digits,
                            selectedOtpData.period
                        );
                        await sendMessage(chatId, `OTP for ${selectedOtpData.issueName} (${selectedOtpData.label}): ${otp}`, env);
                    } catch (otpError) {
                        console.error(`OTP Generation Error for ${selectedOtpData.label} (User: ${userId}):`, otpError);
                        await sendMessage(chatId, `Sorry, an error occurred while generating the OTP for ${selectedOtpData.issueName}. Please contact the administrator if this persists.`, env);
                    }

                    await env.OTP_BOT_SESSIONS.delete(userId);
                    console.log(`Session closed for user ${userId} after OTP selection/attempt.`);
                }
                return new Response('OK', { status: 200 });
            }

            else {
                console.warn(`User ${userId} in unknown session state: ${session.state}. Resetting.`);
                await env.OTP_BOT_SESSIONS.delete(userId);
                await sendMessage(chatId, 'An unexpected error occurred with your session state. Please type /start again.', env);
                return new Response('OK', { status: 200 });
            }

        } catch (error) {
            console.error('Error processing update:', error);
            if (update && update.message && update.message.chat && update.message.chat.id) {
                try {
                    await sendMessage(update.message.chat.id.toString(), 'Sorry, an internal error occurred processing your request.', env);
                } catch (sendError) {
                    console.error("Additionally failed to send error message to user:", sendError);
                }
            }
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};
EOF
echo "src/index.js created."

echo "Attempting to create KV Namespace '$KV_NAMESPACE_NAME'..."
KV_CREATE_OUTPUT=$(wrangler kv namespace create "$KV_NAMESPACE_NAME" 2>&1)
KV_CREATE_EXIT_CODE=$?

if [ $KV_CREATE_EXIT_CODE -ne 0 ]; then
    if echo "$KV_CREATE_OUTPUT" | grep -q "already exists"; then
        echo "KV Namespace '$KV_NAMESPACE_NAME' already exists. Retrieving ID..."
        KV_LIST_OUTPUT=$(wrangler kv namespace list) || fail "Failed to list KV namespaces to find existing ID."
        KV_ID=$(echo "$KV_LIST_OUTPUT" | grep "$KV_NAMESPACE_NAME" | awk '{print $NF}')
        if [ -z "$KV_ID" ]; then
             fail "Namespace '$KV_NAMESPACE_NAME' exists, but could not extract its ID from 'wrangler kv namespace list'. Output:\n$KV_LIST_OUTPUT"
        fi
         echo "Found existing KV Namespace ID: $KV_ID"
    else
        fail "Failed to create KV namespace '$KV_NAMESPACE_NAME'. Exit Code: $KV_CREATE_EXIT_CODE Output:\n$KV_CREATE_OUTPUT"
    fi
else
    echo "$KV_CREATE_OUTPUT"
    KV_ID=$(echo "$KV_CREATE_OUTPUT" | grep -o '[a-f0-9]\{32\}')
    if [ -z "$KV_ID" ]; then
        fail "KV Namespace created, but could not extract ID from output. Output:\n$KV_CREATE_OUTPUT"
    fi
    echo "KV Namespace created successfully with ID: $KV_ID"
fi


echo "Adding KV binding to wrangler.toml..."
cat << EOF >> wrangler.toml

[[kv_namespaces]]
binding = "OTP_BOT_SESSIONS"
id = "$KV_ID"
preview_id = "$KV_ID"
EOF
echo "KV binding added."

echo "Setting secrets (input will be hidden)..."
echo -n "$BOT_TOKEN" | wrangler secret put BOT_TOKEN --name "$WORKER_NAME" || fail "Failed to set BOT_TOKEN secret."
echo "BOT_TOKEN set."
echo -n "$OTP_PASSWORD" | wrangler secret put OTP_PASSWORD --name "$WORKER_NAME" || fail "Failed to set OTP_PASSWORD secret."
echo "OTP_PASSWORD set."
echo "Secrets set for worker '$WORKER_NAME'."

echo "Deploying worker '$WORKER_NAME'..."
DEPLOY_OUTPUT=$(wrangler deploy 2>&1)
DEPLOY_EXIT_CODE=$?

echo "$DEPLOY_OUTPUT"

if [ $DEPLOY_EXIT_CODE -ne 0 ]; then
  fail "Worker deployment failed. See output above."
fi

WORKER_URL=$(echo "$DEPLOY_OUTPUT" | grep -o 'https://[^ ]*\.workers\.dev')

if [ -z "$WORKER_URL" ]; then
  echo "Warning: Could not automatically extract worker URL ending in .workers.dev from deployment output."
  echo "Please find the URL manually (it should be listed in the output above) and set the Telegram webhook if needed."
  WORKER_URL="MANUAL_URL_NEEDED"
else
 echo "Worker deployed successfully. URL: $WORKER_URL"
fi


if [ "$WORKER_URL" != "MANUAL_URL_NEEDED" ]; then
    echo "Setting Telegram webhook to $WORKER_URL ..."
    WEBHOOK_SET_URL="https://api.telegram.org/bot${BOT_TOKEN}/setWebhook"
    RESPONSE=$(curl -sS --fail -X POST -H 'Content-Type: application/json' \
         -d "{\"url\": \"$WORKER_URL\"}" \
         "$WEBHOOK_SET_URL")
    CURL_EXIT_CODE=$?

    if [ $CURL_EXIT_CODE -ne 0 ]; then
        fail "Failed to set Telegram webhook. curl command failed with exit code $CURL_EXIT_CODE. Check network or Bot Token. Response: $RESPONSE"
    fi

    if echo "$RESPONSE" | jq -e '.ok == true' > /dev/null; then
        echo "Telegram webhook set successfully to $WORKER_URL"
        echo "Description: $(echo "$RESPONSE" | jq -r '.description')"
    else
        echo "Warning: Telegram API reported an issue setting the webhook." >&2
        echo "Response: $RESPONSE" >&2
        echo "Please verify the webhook manually using: https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo" >&2
        fail "Telegram API returned 'ok: false' when setting webhook."
    fi
else
    echo "Skipping automatic webhook setup as worker URL could not be determined automatically."
    echo "Please set the webhook manually using:"
    echo "curl -X POST -H 'Content-Type: application/json' -d '{\"url\": \"YOUR_WORKER_URL\"}' https://api.telegram.org/bot${BOT_TOKEN}/setWebhook"
    echo "(Replace YOUR_WORKER_URL with the actual URL from the deployment output above)"
fi


echo ""
echo "--- Deployment Complete ---"
if [ "$WORKER_URL" != "MANUAL_URL_NEEDED" ]; then
    echo "Worker Name: $WORKER_NAME"
    echo "Worker URL: $WORKER_URL"
    echo "KV Namespace: $KV_NAMESPACE_NAME (ID: $KV_ID)"
    echo "Bot should now be responding via the Cloudflare Worker."
else
    echo "Worker Name: $WORKER_NAME"
    echo "KV Namespace: $KV_NAMESPACE_NAME (ID: $KV_ID)"
    echo "Deployment finished, but requires manual webhook setup (see messages above)."
fi
echo "-------------------------"
