import * as readline from 'readline';
import * as mysql from 'mysql';
import { spawn } from 'child_process';
import * as https from 'https';
import { URL } from 'url';

/**
 * Required environment variables:
 * DB_HOST, DB_USER, DB_PASS, DB_NAME, API_URL, API_TOKEN
 */

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

/**
 * FIX (OWASP A07 - Authentication Failures):
 * - Avoid weak/default/hard-coded credentials.
 * - Load DB credentials from environment (or a secrets manager) and fail fast if they look like known defaults.
 */
const dbConfig = {
  host: env('DB_HOST'),
  user: env('DB_USER'),
  password: env('DB_PASS'),
  database: env('DB_NAME'),
};

// Known demo/default values from the review screenshots (reject to prevent accidental insecure deployments).
const DISALLOWED_DEFAULTS = new Set(['mydatabase.com', 'admin', 'secret123', 'mydb']);
for (const [key, value] of Object.entries(dbConfig)) {
  if (DISALLOWED_DEFAULTS.has(value)) {
    throw new Error(
      `Refusing to run with a known default DB ${key} value ("${value}"). ` +
        `Set strong, unique credentials (OWASP A07).`
    );
  }
}

function validateName(input: string): string {
  const name = input.trim();

  /**
   * FIX (OWASP A05 - Injection):
   * - Treat all user input as untrusted.
   * - Apply an allowlist + length limit for a "name" so unexpected characters don't flow into sinks.
   */
  if (!/^[A-Za-z][A-Za-z '\-]{0,48}[A-Za-z]$/.test(name)) {
    throw new Error("Invalid name. Use letters/spaces/apostrophes/hyphens (2–50 chars).");
  }
  return name;
}

function getUserInput(): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  return new Promise((resolve, reject) => {
    rl.question('Enter your name: ', (answer) => {
      rl.close();
      try {
        // FIX (OWASP A05 - Injection): validate/normalize user input at the boundary.
        resolve(validateName(answer));
      } catch (e) {
        reject(e);
      }
    });
  });
}

function validateEmail(to: string): string {
  const email = to.trim();

  // Basic validation to prevent obvious invalid values from reaching the command.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.startsWith('-')) {
    throw new Error('Invalid email address.');
  }
  return email;
}

function sanitizeHeaderValue(value: string, maxLen: number): string {
  // Prevent CR/LF injection into mail headers.
  const v = value.replace(/[\r\n]+/g, ' ').trim();
  if (!v || v.length > maxLen) throw new Error('Invalid subject.');
  return v;
}

function sendEmail(to: string, subject: string, body: string): Promise<void> {
  /**
   * FIX (OWASP A05 - Injection):
   * - DO NOT build shell commands with untrusted strings (exec + template strings).
   * - Use spawn/execFile-style APIs with an argument array so no shell interprets input.
   */
  const safeTo = validateEmail(to);
  const safeSubject = sanitizeHeaderValue(subject, 120);

  return new Promise((resolve, reject) => {
    // Using spawn avoids shell expansion/interpretation -> mitigates command injection.
    const mail = spawn('mail', ['-s', safeSubject, safeTo], { stdio: ['pipe', 'ignore', 'pipe'] });

    mail.on('error', reject);
    mail.stderr.on('data', (d) => console.error(String(d).trim()));
    mail.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`mail exited with code ${code}`))));

    // Body is written to stdin as data (not executed).
    mail.stdin.write(body);
    mail.stdin.end();
  });
}

const MAX_API_BYTES = 1024 * 1024; // 1MB

function getData(): Promise<string> {
  /**
   * FIX (OWASP A01 - Broken Access Control):
   * - Use an authenticated endpoint (send an Authorization token) instead of calling an open/insecure API.
   * - Enforce HTTPS so the response can’t be trivially intercepted/tampered with in transit.
   */
  const apiUrl = new URL(env('API_URL')); // e.g. https://api.example.com/get-data
  if (apiUrl.protocol !== 'https:') throw new Error('API_URL must use https:// (OWASP principle: secure by default).');

  const token = env('API_TOKEN'); // e.g. Bearer token / API key

  return new Promise((resolve, reject) => {
    const req = https.get(
      apiUrl,
      { headers: { Authorization: `Bearer ${token}` } },
      (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume(); // drain response
          reject(new Error(`API request failed with status ${res.statusCode}`));
          return;
        }

        res.setEncoding('utf8');
        let data = '';
        let bytes = 0;

        res.on('data', (chunk: string) => {
          bytes += Buffer.byteLength(chunk, 'utf8');
          if (bytes > MAX_API_BYTES) {
            req.destroy(new Error('API response too large'));
            return;
          }
          data += chunk;
        });

        res.on('end', () => resolve(data));
      }
    );

    req.on('error', reject);
  });
}

function saveToDb(data: string): Promise<void> {
  /**
   * FIX (OWASP A05 - Injection):
   * - Never concatenate untrusted data into SQL strings.
   * - Use parameterized queries (placeholders) so data is sent separately from SQL code.
   */
  const safeData = data.trim();
  if (!safeData || safeData.length > 1024) {
    throw new Error('API data is empty or unexpectedly large.');
  }

  const connection = mysql.createConnection(dbConfig);
  const sql = 'INSERT INTO mytable (column1, column2) VALUES (?, ?)';

  return new Promise((resolve, reject) => {
    connection.query(sql, [safeData, 'Another Value'], (error) => {
      connection.end();

      if (error) return reject(error);
      console.log('Data saved');
      resolve();
    });
  });
}

(async () => {
  try {
    const userName = await getUserInput();
    const data = await getData();

    await saveToDb(data);

    // Email sending now avoids shell injection and validates headers/recipient.
    await sendEmail('admin@example.com', 'User Input', userName);
  } catch (err) {
    // Keep error output minimal (don’t echo secrets).
    console.error('Fatal error:', (err as Error).message);
    process.exitCode = 1;
  }
})();
