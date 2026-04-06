import axios from "axios";

const API_BASE =
  import.meta.env.VITE_API_BASE ||
  "https://4xhy1jajvb.execute-api.ap-south-1.amazonaws.com/dev";

export const CSV_BUCKET_URL =
  import.meta.env.VITE_CSV_BUCKET ||
  "https://csv-output-buckett.s3.amazonaws.com/";

const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000, // 60s — cross-account scans can take longer
  headers: { "Content-Type": "application/json" },
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const message =
      err.response?.data?.message || err.message || "An unexpected error occurred";
    return Promise.reject(new Error(message));
  }
);

// Trigger a scan for the given target accountId (required — no own-account scanning)
export const runScan = (accountId) => {
  return api.get(`/scan?accountId=${accountId}`);
};

// Fetch findings scoped to a specific accountId (required)
export const getFindings = (accountId) => {
  return api.get(`/findings?accountId=${accountId}`);
};

// Refresh / generate CSV report scoped to a specific accountId (required)
export const refreshFindings = (accountId) => {
  return api.get(`/refresh?accountId=${accountId}`);
};

export const listReports = async () => {
  try {
    const response = await axios.get(CSV_BUCKET_URL, { timeout: 10000 });
    const parser   = new DOMParser();
    const xml      = parser.parseFromString(response.data, "text/xml");
    const keys     = Array.from(xml.querySelectorAll("Key")).map((k) => k.textContent);
    return keys.filter((k) => k.endsWith(".csv")).sort().reverse();
  } catch {
    return [];
  }
};

export const getReportDownloadUrl = (filename) => `${CSV_BUCKET_URL}${filename}`;

export default api;