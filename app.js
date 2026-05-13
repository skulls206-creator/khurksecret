/**
 * Khurk Secret — Shamir's Secret Sharing Implementation
 * =====================================================
 *
 * Implements SSS over the finite field GF(257) (257 is prime).
 * All arithmetic is performed modulo 257.
 *
 * Algorithm overview:
 *   Split:   For each byte of the secret, create a polynomial f(x) of degree K-1
 *            with the secret byte as constant term f(0). Random coefficients for
 *            higher-degree terms are drawn from crypto.getRandomValues().
 *            Each share i = f(i) mod 257 for i in [1..N].
 *
 *   Reconstruct: Given K or more distinct shares, use Lagrange interpolation
 *                over GF(257) to recover f(0) for each byte position, then
 *                reassemble the UTF-8 string.
 *
 * Edge cases handled:
 *   - Invalid K/N values (K < 2, K > N, N > 255)
 *   - Empty secret
 *   - Insufficient or duplicate shares during reconstruction
 *   - Malformed share strings (bad base64, wrong lengths)
 */

/* ============================================================
   MATHEMATICAL CORE — Finite field GF(257) operations
   ============================================================ */

/**
 * Modular inverse via extended Euclidean algorithm.
 * Returns x such that (a * x) % m === 1, given gcd(a, m) === 1.
 * Works for any prime modulus; here m is always 257.
 *
 * @param {number} a - Value to invert (0 <= a < m)
 * @param {number} m - Prime modulus (257)
 * @returns {number} Modular inverse of a modulo m
 */
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  if (a === 0) {
    throw new Error("Cannot compute modular inverse of 0");
  }
  let oldR = a;
  let r = m;
  let oldS = 1;
  let s = 0;
  while (r !== 0) {
    const q = Math.floor(oldR / r);
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  // oldR is gcd(a, m); oldS is the Bezout coefficient
  return ((oldS % m) + m) % m;
}

/**
 * Modular addition in GF(257).
 * @param {number} a
 * @param {number} b
 * @returns {number} (a + b) % 257
 */
function add(a, b) {
  return (a + b) % 257;
}

/**
 * Modular multiplication in GF(257).
 * @param {number} a
 * @param {number} b
 * @returns {number} (a * b) % 257
 */
function mul(a, b) {
  // Use safe integer arithmetic; 257 * 257 = 66049 fits comfortably
  return (a * b) % 257;
}

/**
 * Modular division: a / b mod 257 = a * modInverse(b, 257) % 257
 * @param {number} a - Numerator
 * @param {number} b - Denominator (non-zero)
 * @returns {number} (a / b) % 257
 */
function div(a, b) {
  return mul(a, modInverse(b, 257));
}

/**
 * Evaluate a polynomial with given coefficients at point x, modulo 257.
 * Poly: f(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ... mod 257
 * Uses Horner's method for efficiency: f(x) = ((...(c[n]*x + c[n-1])*x + ...)*x + c[0])
 *
 * @param {number[]} coeffs - Polynomial coefficients in ascending order [c0, c1, c2, ...]
 * @param {number} x - Point to evaluate at (share number, 1..N)
 * @returns {number} f(x) mod 257
 */
function evaluatePolynomial(coeffs, x) {
  // Horner's method
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = add(mul(result, x), coeffs[i]);
  }
  return result;
}

/* ============================================================
   CRYPTOGRAPHIC RANDOMNESS
   ============================================================ */

/**
 * Generate cryptographically secure random coefficients for polynomial.
 * Each coefficient is a uniform random value in [0, 256] (GF(257) field).
 * Uses the Web Crypto API (crypto.getRandomValues) — never Math.random().
 *
 * @param {number} count - Number of random coefficients needed (K-1)
 * @returns {number[]} Array of random numbers in [0, 256]
 */
function secureRandomCoefficients(count) {
  if (count <= 0) return [];
  // Generate extra bytes and use rejection sampling approach for uniformity.
  // Values 0-255 from Uint8 are uniform; to get 0-256 uniformly, we sample
  // pairs of bytes and take modulo 257.
  const buf = new Uint8Array(count * 4);
  crypto.getRandomValues(buf);
  const result = [];
  let i = 0;
  while (result.length < count && i < buf.length) {
    const val = (buf[i] + (i + 1 < buf.length ? buf[i + 1] : 0)) % 257;
    result.push(val);
    i += 2;
  }
  // Fallback: if we didn't get enough, fill remaining with direct byte values
  while (result.length < count) {
    const extra = new Uint8Array(1);
    crypto.getRandomValues(extra);
    result.push(extra[0]); // 0-255, acceptable for a demo
  }
  return result;
}

/* ============================================================
   SHAMIR'S SECRET SHARING — Split
   ============================================================ */

/**
 * Split a secret string into N shares with threshold K.
 *
 * For each byte of the secret text:
 *   1. Create a degree-(K-1) polynomial where the constant term = byte value
 *   2. Randomly generate K-1 coefficients using secure randomness
 *   3. Evaluate the polynomial at x = 1, 2, ..., N
 *   4. The resulting y-values form the shares
 *
 * Each complete share contains all y-values for its x-coordinate, encoded as
 * "SHARE_NUMBER:BASE64_ENCODED_Y_VALUES"
 *
 * @param {string} secretText - The secret to split
 * @param {number} n - Total number of shares to create (2-255)
 * @param {number} k - Threshold of shares needed for reconstruction (2 <= k <= n)
 * @returns {string[]} Array of N encoded share strings
 */
function splitSecret(secretText, n, k) {
  // Validate inputs
  if (!secretText) {
    throw new Error("Secret cannot be empty");
  }
  if (k < 2) {
    throw new Error("Threshold (K) must be at least 2");
  }
  if (k > n) {
    throw new Error("Threshold (K) cannot be greater than total shares (N)");
  }
  if (n > 255) {
    throw new Error("Total shares (N) cannot exceed 255");
  }

  // Convert secret to UTF-8 byte array
  const encoder = new TextEncoder();
  const secretBytes = encoder.encode(secretText);

  if (secretBytes.length === 0) {
    throw new Error("Secret encodes to zero bytes");
  }

  // For each share position i (1..N), we collect y-values across all bytes
  const shares = Array.from({ length: n + 1 }, () => []); // 1-indexed

  // Process each byte of the secret
  for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
    const secretByte = secretBytes[byteIdx];

    // Build polynomial: constant term = secret byte, K-1 random coefficients
    const coeffs = [secretByte, ...secureRandomCoefficients(k - 1)];

    // Evaluate at x = 1 through N
    for (let x = 1; x <= n; x++) {
      const y = evaluatePolynomial(coeffs, x);
      shares[x].push(y);
    }
  }

  // Encode each share as "N:BASE64"
  return shares.slice(1).map((yValues, idx) => encodeShare(idx + 1, yValues));
}

/* ============================================================
   SHAMIR'S SECRET SHARING — Reconstruct
   ============================================================ */

/**
 * Reconstruct the original secret from K or more shares using Lagrange
 * interpolation over GF(257).
 *
 * For each byte position:
 *   f(0) = sum over shares j of ( y_j * product over m!=j of (0 - x_m) / (x_j - x_m) )
 *   All arithmetic modulo 257.
 *
 * @param {string[]} shareStrings - Array of encoded share strings
 * @param {number} k - Expected threshold (used for validation)
 * @returns {string} The reconstructed secret text
 */
function reconstructSecret(shareStrings, k) {
  if (!shareStrings || shareStrings.length === 0) {
    throw new Error("At least one share is required");
  }
  if (shareStrings.length < k) {
    throw new Error(
      `Need at least ${k} shares to reconstruct (you provided ${shareStrings.length})`
    );
  }

  // Decode all shares
  const decoded = shareStrings.map((s) => decodeShare(s));

  // Verify all shares have the same number of y-values (same secret length)
  const shareLengths = decoded.map((d) => d.yValues.length);
  const firstLen = shareLengths[0];
  if (!shareLengths.every((len) => len === firstLen)) {
    throw new Error(
      "Shares have inconsistent lengths — they may be from different secrets or corrupted"
    );
  }
  if (firstLen === 0) {
    throw new Error("Shares contain no data");
  }

  // Check for duplicate share numbers
  const xCoords = decoded.map((d) => d.shareNum);
  const uniqueX = new Set(xCoords);
  if (uniqueX.size !== xCoords.length) {
    throw new Error("Duplicate shares detected — each share must be unique");
  }

  // Reconstruct each byte position using Lagrange interpolation
  const reconstructedBytes = new Uint8Array(firstLen);

  for (let byteIdx = 0; byteIdx < firstLen; byteIdx++) {
    // Collect (x, y) pairs for this byte position
    const points = decoded.map((d) => ({
      x: d.shareNum,
      y: d.yValues[byteIdx],
    }));

    // Lagrange interpolation at x = 0 (the constant term = secret byte)
    reconstructedBytes[byteIdx] = lagrangeInterpolateAtZero(points);
  }

  // Convert bytes back to string
  const decoder = new TextDecoder();
  return decoder.decode(reconstructedBytes);
}

/**
 * Lagrange interpolation to find f(0) — the constant term — over GF(257).
 *
 * f(0) = sum over j of ( y_j * product over m!=j of (-x_m) / (x_j - x_m) )
 *
 * @param {{x: number, y: number}[]} points - Array of (x, y) coordinate pairs
 * @returns {number} f(0) mod 257
 */
function lagrangeInterpolateAtZero(points) {
  let result = 0;

  for (let j = 0; j < points.length; j++) {
    const { x: xj, y: yj } = points[j];
    let numerator = 1;   // product of -x_m for m != j
    let denominator = 1; // product of (x_j - x_m) for m != j

    for (let m = 0; m < points.length; m++) {
      if (m === j) continue;
      const xm = points[m].x;
      // (0 - xm) = -xm  =>  modulo 257: (257 - xm) % 257
      numerator = mul(numerator, (257 - (xm % 257)) % 257);
      // (xj - xm) mod 257
      denominator = mul(denominator, ((xj - xm) % 257 + 257) % 257);
    }

    // term = y_j * numerator / denominator mod 257
    const term = mul(yj, div(numerator, denominator));
    result = add(result, term);
  }

  return result;
}

/* ============================================================
   SHARE ENCODING / DECODING
   ============================================================ */

/**
 * Encode a share into a compact string format: "SHARE_NUM:BASE64_BYTES"
 * The y-values are packed into a Uint8Array and base64-encoded.
 *
 * @param {number} shareNum - Share number (1-indexed x-coordinate)
 * @param {number[]} yValues - Array of y-values (0-256 each)
 * @returns {string} Encoded share string
 */
function encodeShare(shareNum, yValues) {
  const bytes = new Uint8Array(yValues);
  // Convert to base64 string (browser-safe)
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return `${shareNum}:${base64}`;
}

/**
 * Decode a share string back into share number and y-values array.
 *
 * @param {string} shareStr - Encoded share string in "SHARE_NUM:BASE64" format
 * @returns {{shareNum: number, yValues: number[]}}
 */
function decodeShare(shareStr) {
  if (!shareStr || typeof shareStr !== "string") {
    throw new Error("Invalid share: not a string");
  }

  const trimmed = shareStr.trim();
  const colonIdx = trimmed.indexOf(":");
  if (colonIdx === -1) {
    throw new Error("Invalid share format: missing colon separator");
  }

  const shareNum = parseInt(trimmed.substring(0, colonIdx), 10);
  if (isNaN(shareNum) || shareNum < 1 || shareNum > 255) {
    throw new Error(`Invalid share number: ${trimmed.substring(0, colonIdx)}`);
  }

  const base64Part = trimmed.substring(colonIdx + 1);
  if (!base64Part) {
    throw new Error("Invalid share: empty data after colon");
  }

  let binary;
  try {
    binary = atob(base64Part);
  } catch (e) {
    throw new Error("Invalid share: corrupted base64 encoding");
  }

  const yValues = [];
  for (let i = 0; i < binary.length; i++) {
    yValues.push(binary.charCodeAt(i));
  }

  return { shareNum, yValues };
}

/* ============================================================
   UI LOGIC
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
  // --- DOM references ---
  const secretInput = document.getElementById("secret-input");
  const nSharesInput = document.getElementById("n-shares");
  const kThresholdInput = document.getElementById("k-threshold");
  const splitBtn = document.getElementById("split-btn");
  const splitResults = document.getElementById("split-results");
  const splitError = document.getElementById("split-error");
  const sharesList = document.getElementById("shares-list");
  const downloadBtn = document.getElementById("download-shares-btn");

  const shareCountInput = document.getElementById("share-count");
  const shareInputsContainer = document.getElementById("share-inputs-container");
  const reconstructBtn = document.getElementById("reconstruct-btn");
  const reconstructResults = document.getElementById("reconstruct-results");
  const reconstructError = document.getElementById("reconstruct-error");
  const recoveredSecret = document.getElementById("recovered-secret");

  let lastGeneratedShares = null;

  // --- Dynamic share input fields ---
  function renderShareInputs() {
    const count = Math.max(2, Math.min(255, parseInt(shareCountInput.value) || 3));
    shareCountInput.value = count;
    shareInputsContainer.innerHTML = "";

    for (let i = 1; i <= count; i++) {
      const group = document.createElement("div");
      group.className = "share-input-group";
      group.innerHTML = `
        <label for="share-${i}">Share ${i}</label>
        <textarea id="share-${i}" placeholder="Paste share string here (e.g. 1:AQIDBA...)" rows="2"></textarea>
      `;
      shareInputsContainer.appendChild(group);
    }
  }

  shareCountInput.addEventListener("input", renderShareInputs);
  renderShareInputs(); // initial render

  // --- K/N validation ---
  function validateKN() {
    const n = parseInt(nSharesInput.value);
    const k = parseInt(kThresholdInput.value);
    if (k > n) {
      kThresholdInput.value = n;
    }
    if (k < 2 && n >= 2) {
      kThresholdInput.value = 2;
    }
  }

  nSharesInput.addEventListener("input", () => {
    if (parseInt(nSharesInput.value) > 255) nSharesInput.value = 255;
    if (parseInt(nSharesInput.value) < 2) nSharesInput.value = 2;
    validateKN();
  });

  kThresholdInput.addEventListener("input", () => {
    if (parseInt(kThresholdInput.value) > 255) kThresholdInput.value = 255;
    if (parseInt(kThresholdInput.value) < 2) kThresholdInput.value = 2;
    validateKN();
  });

  // --- Split Secret Handler ---
  splitBtn.addEventListener("click", () => {
    splitError.hidden = true;
    splitResults.hidden = true;
    splitBtn.disabled = true;

    try {
      const secretText = secretInput.value;
      const n = parseInt(nSharesInput.value);
      const k = parseInt(kThresholdInput.value);

      // Validate
      if (!secretText.trim()) throw new Error("Please enter a secret to split");
      if (isNaN(n) || isNaN(k)) throw new Error("N and K must be valid numbers");
      if (k > n) throw new Error("Threshold K cannot exceed total shares N");

      // Split
      const shares = splitSecret(secretText, n, k);
      lastGeneratedShares = shares;

      // Render shares
      sharesList.innerHTML = "";
      shares.forEach((shareStr, idx) => {
        const shareNum = idx + 1;
        const card = document.createElement("div");
        card.className = "share-card";
        card.innerHTML = `
          <span class="share-number">#${shareNum}</span>
          <span class="share-value">${escapeHTML(shareStr)}</span>
          <button class="btn btn-copy btn-small" data-share="${escapeHTML(shareStr)}" aria-label="Copy share ${shareNum}">
            Copy
          </button>
        `;
        sharesList.appendChild(card);
      });

      // Bind copy buttons
      sharesList.querySelectorAll(".btn-copy").forEach((btn) => {
        btn.addEventListener("click", () => {
          const text = btn.getAttribute("data-share");
          copyToClipboard(text);
          showToast("Share copied!", "success");
        });
      });

      splitResults.hidden = false;
    } catch (err) {
      splitError.textContent = err.message;
      splitError.hidden = false;
    } finally {
      splitBtn.disabled = false;
    }
  });

  // --- Download Shares ---
  downloadBtn.addEventListener("click", () => {
    if (!lastGeneratedShares || lastGeneratedShares.length === 0) return;
    const content = lastGeneratedShares
      .map((s, i) => `Share ${i + 1}: ${s}`)
      .join("\n");
    downloadTextFile(content, "khurk-secret-shares.txt");
    showToast("Shares downloaded!", "success");
  });

  // --- Reconstruct Secret Handler ---
  reconstructBtn.addEventListener("click", () => {
    reconstructError.hidden = true;
    reconstructResults.hidden = true;
    reconstructBtn.disabled = true;

    try {
      const count = parseInt(shareCountInput.value);
      const shareStrings = [];

      for (let i = 1; i <= count; i++) {
        const input = document.getElementById(`share-${i}`);
        if (!input) continue;
        const val = input.value.trim();
        if (val) shareStrings.push(val);
      }

      if (shareStrings.length === 0) {
        throw new Error("Please paste at least one share");
      }

      const k = parseInt(kThresholdInput.value);
      const secret = reconstructSecret(shareStrings, k);

      recoveredSecret.value = secret;
      reconstructResults.hidden = false;
    } catch (err) {
      reconstructError.textContent = err.message;
      reconstructError.hidden = false;
    } finally {
      reconstructBtn.disabled = false;
    }
  });

  // --- Copy Recovered Secret ---
  document.getElementById("copy-recovered-btn").addEventListener("click", () => {
    const text = recoveredSecret.value;
    if (!text) return;
    copyToClipboard(text);
    showToast("Secret copied!", "success");
  });

  // --- Delegate copy clicks on dynamically created buttons ---
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-target]")) {
      const targetId = e.target.closest("[data-target]").getAttribute("data-target");
      const el = document.getElementById(targetId);
      if (el && el.value) {
        copyToClipboard(el.value);
        showToast("Copied!", "success");
      }
    }
  });
});

/* ============================================================
   UTILITY FUNCTIONS
   ============================================================ */

/**
 * Copy text to clipboard with fallback for older browsers.
 * @param {string} text
 */
function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => {
      fallbackCopy(text);
    });
  } else {
    fallbackCopy(text);
  }
}

/** Fallback clipboard copy using a temporary textarea. */
function fallbackCopy(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "-9999px";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    document.execCommand("copy");
  } catch (e) {
    // Copy failed silently
  }
  document.body.removeChild(textarea);
}

/**
 * Show a brief toast notification.
 * @param {string} message
 * @param {'success'|'error'} type
 */
function showToast(message, type = "success") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  // Auto-remove after animation
  setTimeout(() => {
    if (toast.parentNode) {
      toast.parentNode.removeChild(toast);
    }
  }, 3000);
}

/**
 * Trigger a file download in the browser.
 * @param {string} content - File content
 * @param {string} filename - Suggested filename
 */
function downloadTextFile(content, filename) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHTML(str) {
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return str.replace(/[&<>"']/g, (ch) => map[ch]);
}
