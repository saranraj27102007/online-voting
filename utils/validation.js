// PAN Card regex validation
const PAN_REGEX = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;

function validatePAN(pan) {
  return PAN_REGEX.test(pan?.toUpperCase?.() || '');
}

// Fuzzy name matching using Levenshtein distance
function levenshteinDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function nameSimilarity(name1, name2) {
  if (!name1 || !name2) return 0;
  const a = name1.toLowerCase().trim();
  const b = name2.toLowerCase().trim();
  if (a === b) return 1;

  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;

  const distance = levenshteinDistance(a, b);
  return 1 - distance / maxLen;
}

// Calculate age from DOB string (YYYY-MM-DD or DD/MM/YYYY)
function calculateAge(dob) {
  let birthDate;

  if (dob.includes('-')) {
    birthDate = new Date(dob);
  } else if (dob.includes('/')) {
    const parts = dob.split('/');
    if (parts[0].length === 4) {
      birthDate = new Date(`${parts[0]}-${parts[1]}-${parts[2]}`);
    } else {
      birthDate = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
    }
  } else {
    birthDate = new Date(dob);
  }

  if (isNaN(birthDate.getTime())) return null;

  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const m = today.getMonth() - birthDate.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
}

function validatePhone(phone) {
  return /^[6-9]\d{9}$/.test(phone.replace(/\s/g, ''));
}

function sanitizeString(str) {
  if (!str) return '';
  return str.toString().trim().replace(/[<>]/g, '');
}

function normalizeDate(dob) {
  if (!dob) return null;
  // Convert to YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(dob)) return dob;
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(dob)) {
    const [d, m, y] = dob.split('/');
    return `${y}-${m}-${d}`;
  }
  if (/^\d{2}-\d{2}-\d{4}$/.test(dob)) {
    const [d, m, y] = dob.split('-');
    return `${y}-${m}-${d}`;
  }
  return dob;
}

module.exports = {
  validatePAN,
  nameSimilarity,
  calculateAge,
  validatePhone,
  sanitizeString,
  normalizeDate
};
