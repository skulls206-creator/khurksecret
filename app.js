"use strict";

/**
 * Khurk Secret — Shamir's Secret Sharing Implementation
 * =====================================================
 *
 * Implements SSS over the finite field GF(256) using log/antilog tables
 * with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
 * All arithmetic uses XOR for addition and table lookups for multiplication.
 *
 * Algorithm overview:
 *   Split:   For each byte of the secret, create a polynomial f(x) of degree K-1
 *            with the secret byte as constant term f(0). Random coefficients for
 *            higher-degree terms are drawn from crypto.getRandomValues().
 *            Each share i = f(i) in GF(256) for i in [1..N].
 *
 *   Reconstruct: Given K or more distinct shares, use Lagrange interpolation
 *                over GF(256) to recover f(0) for each byte position, then
 *                reassemble the UTF-8 string.
 *
 * Edge cases handled:
 *   - Invalid K/N values (K < 2, K > N, N > 255)
 *   - Empty secret
 *   - Insufficient or duplicate shares during reconstruction
 *   - Malformed share strings (bad base64, wrong lengths)
 */

/* ============================================================
   FINITE FIELD GF(256) — log/antilog tables
   Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11D
   ============================================================ */

const gfLog = new Uint8Array(256);
const gfExp = new Uint8Array(510);

(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    gfExp[i] = x;
    gfLog[x] = i;
    x = (x << 1) ^ (x & 0x80 ? 0x1D : 0);
    x &= 0xFF;
  }
  for (let i = 255; i < 510; i++) {
    gfExp[i] = gfExp[i - 255];
  }
})();

function gfAdd(a, b) {
  return a ^ b;
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return gfExp[gfLog[a] + gfLog[b]];
}

function gfDiv(a, b) {
  if (b === 0) throw new Error("Division by zero in GF(256)");
  if (a === 0) return 0;
  return gfExp[(gfLog[a] - gfLog[b] + 255) % 255];
}

function gfInverse(a) {
  if (a === 0) throw new Error("Cannot invert zero in GF(256)");
  return gfExp[255 - gfLog[a]];
}

function evaluatePolynomial(coeffs, x) {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coeffs[i]);
  }
  return result;
}

/* ============================================================
   CRYPTOGRAPHIC RANDOMNESS
   ============================================================ */

function secureRandomCoefficients(count) {
  if (count <= 0) return [];
  const buf = new Uint8Array(count);
  crypto.getRandomValues(buf);
  return Array.from(buf);
}

/* ============================================================
   SHAMIR'S SECRET SHARING — Split
   ============================================================ */

function splitSecret(secretText, n, k) {
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

  const encoder = new TextEncoder();
  const secretBytes = encoder.encode(secretText);

  if (secretBytes.length === 0) {
    throw new Error("Secret encodes to zero bytes");
  }

  const shares = Array.from({ length: n + 1 }, () => []);

  for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
    const secretByte = secretBytes[byteIdx];
    const coeffs = [secretByte, ...secureRandomCoefficients(k - 1)];

    for (let x = 1; x <= n; x++) {
      const y = evaluatePolynomial(coeffs, x);
      shares[x].push(y);
    }
  }

  return shares.slice(1).map((yValues, idx) => encodeShare(idx + 1, yValues));
}

/* ============================================================
   SHAMIR'S SECRET SHARING — Reconstruct
   ============================================================ */

function reconstructSecret(shareStrings, k) {
  if (!shareStrings || shareStrings.length === 0) {
    throw new Error("At least one share is required");
  }
  if (shareStrings.length < k) {
    throw new Error(
      `Need at least ${k} shares to reconstruct (you provided ${shareStrings.length})`
    );
  }

  const decoded = shareStrings.map((s) => decodeShare(s));

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

  const xCoords = decoded.map((d) => d.shareNum);
  const uniqueX = new Set(xCoords);
  if (uniqueX.size !== xCoords.length) {
    throw new Error("Duplicate shares detected — each share must be unique");
  }

  const reconstructedBytes = new Uint8Array(firstLen);

  for (let byteIdx = 0; byteIdx < firstLen; byteIdx++) {
    const points = decoded.map((d) => ({
      x: d.shareNum,
      y: d.yValues[byteIdx],
    }));
    reconstructedBytes[byteIdx] = lagrangeInterpolateAtZero(points);
  }

  const decoder = new TextDecoder();
  return decoder.decode(reconstructedBytes);
}

function lagrangeInterpolateAtZero(points) {
  let result = 0;

  for (let j = 0; j < points.length; j++) {
    const { x: xj, y: yj } = points[j];
    let numerator = 1;
    let denominator = 1;

    for (let m = 0; m < points.length; m++) {
      if (m === j) continue;
      const xm = points[m].x;
      numerator = gfMul(numerator, xm);
      denominator = gfMul(denominator, gfAdd(xj, xm));
    }

    result = gfAdd(result, gfMul(yj, gfDiv(numerator, denominator)));
  }

  return result;
}

/* ============================================================
   SHARE ENCODING / DECODING
   ============================================================ */

function encodeShare(shareNum, yValues) {
  const bytes = new Uint8Array(yValues);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return `${shareNum}:${base64}`;
}

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
  const secretInput = document.getElementById("secret-input");
  const nSharesInput = document.getElementById("n-shares");
  const kThresholdInput = document.getElementById("k-threshold");
  const splitBtn = document.getElementById("split-btn");
  const splitResults = document.getElementById("split-results");
  const splitError = document.getElementById("split-error");
  const sharesList = document.getElementById("shares-list");
  const downloadBtn = document.getElementById("download-shares-btn");

  const shareCountInput = document.getElementById("share-count");
  const reconstructKInput = document.getElementById("reconstruct-k-threshold");
  const shareInputsContainer = document.getElementById("share-inputs-container");
  const reconstructBtn = document.getElementById("reconstruct-btn");
  const reconstructResults = document.getElementById("reconstruct-results");
  const reconstructError = document.getElementById("reconstruct-error");
  const recoveredSecret = document.getElementById("recovered-secret");

  let lastGeneratedShares = null;

  /* --- Dynamic share input fields --- */
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

  renderShareInputs();

  /* --- Split panel K/N validation --- */
  function validateSplitKN() {
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
    validateSplitKN();
  });

  kThresholdInput.addEventListener("input", () => {
    if (parseInt(kThresholdInput.value) > 255) kThresholdInput.value = 255;
    if (parseInt(kThresholdInput.value) < 2) kThresholdInput.value = 2;
    validateSplitKN();
  });

  /* --- Reconstruct panel K / share count validation --- */
  function validateReconstructK() {
    const count = parseInt(shareCountInput.value);
    let k = parseInt(reconstructKInput.value);
    if (k > count) {
      reconstructKInput.value = count;
    }
    if (k < 2 && count >= 2) {
      reconstructKInput.value = 2;
    }
  }

  shareCountInput.addEventListener("input", () => {
    renderShareInputs();
    validateReconstructK();
  });

  reconstructKInput.addEventListener("input", () => {
    if (parseInt(reconstructKInput.value) > 255) reconstructKInput.value = 255;
    if (parseInt(reconstructKInput.value) < 2) reconstructKInput.value = 2;
    validateReconstructK();
  });

  /* --- Split Secret Handler --- */
  splitBtn.addEventListener("click", () => {
    splitError.hidden = true;
    splitResults.hidden = true;
    splitBtn.disabled = true;

    try {
      const secretText = secretInput.value;
      const n = parseInt(nSharesInput.value);
      const k = parseInt(kThresholdInput.value);

      if (!secretText.trim()) throw new Error("Please enter a secret to split");
      if (isNaN(n) || isNaN(k)) throw new Error("N and K must be valid numbers");
      if (k > n) throw new Error("Threshold K cannot exceed total shares N");

      const shares = splitSecret(secretText, n, k);
      lastGeneratedShares = shares;

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

  /* --- Download Shares --- */
  downloadBtn.addEventListener("click", () => {
    if (!lastGeneratedShares || lastGeneratedShares.length === 0) return;
    const content = lastGeneratedShares
      .map((s, i) => `Share ${i + 1}: ${s}`)
      .join("\n");
    downloadTextFile(content, "khurk-secret-shares.txt");
    showToast("Shares downloaded!", "success");
  });

  /* --- Reconstruct Secret Handler --- */
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

      const k = parseInt(reconstructKInput.value);
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

  /* --- Copy Recovered Secret --- */
  document.getElementById("copy-recovered-btn").addEventListener("click", () => {
    const text = recoveredSecret.value;
    if (!text) return;
    copyToClipboard(text);
    showToast("Secret copied!", "success");
  });

  /* --- Delegate copy clicks on dynamically created buttons --- */
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

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => {
      fallbackCopy(text);
    });
  } else {
    fallbackCopy(text);
  }
}

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
  }
  document.body.removeChild(textarea);
}

function showToast(message, type = "success") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) {
      toast.parentNode.removeChild(toast);
    }
  }, 3000);
}

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
