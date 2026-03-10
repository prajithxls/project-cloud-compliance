import axios from "axios";

// ============================================================
// CONFIGURATION — Replace with your actual API Gateway URL
// ============================================================
const API_BASE =
  import.meta.env.VITE_API_BASE ||
  "https://4xhy1jajvb.execute-api.ap-south-1.amazonaws.com/dev";

export const CSV_BUCKET_URL =
  import.meta.env.VITE_CSV_BUCKET ||
  "https://csv-output-buckett.s3.amazonaws.com/";

// ============================================================
// Axios Instance
// ============================================================
const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
  },
});

// ============================================================
// Request interceptor — attach auth headers if needed
// ============================================================
api.interceptors.request.use((config) => {
  // Add API key or auth here if you add Cognito/JWT later
  // config.headers['x-api-key'] = 'YOUR_API_KEY';
  return config;
});

// ============================================================
// Response interceptor — normalize errors
// ============================================================
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const message =
      err.response?.data?.message ||
      err.message ||
      "An unexpected error occurred";
    return Promise.reject(new Error(message));
  }
);

// ============================================================
// API Functions
// ============================================================

/** Trigger the full compliance scan */
export const runScan = () => api.get("/scan");

/** Trigger scan for a specific resource type */
export const runScanByType = (type) => api.get(`/scan/${type.toLowerCase()}`);

/** Fetch all findings from DynamoDB */
export const getFindings = () => api.get("/findings");

/** Fetch findings with pagination */
export const getFindingsPaged = (page = 1, limit = 20) =>
  api.get("/findings", { params: { page, limit } });

/** Refresh findings + generate new CSV */
export const refreshFindings = () => api.get("/refresh");

/** List available CSV reports from S3 */
export const listReports = async () => {
  try {
    const response = await axios.get(CSV_BUCKET_URL, { timeout: 10000 });
    // Parse S3 XML listing
    const parser = new DOMParser();
    const xml = parser.parseFromString(response.data, "text/xml");
    const keys = Array.from(xml.querySelectorAll("Key")).map((k) => k.textContent);
    return keys
      .filter((k) => k.endsWith(".csv"))
      .sort()
      .reverse(); // newest first
  } catch {
    return [];
  }
};

/** Download URL for a specific report file */
export const getReportDownloadUrl = (filename) =>
  `${CSV_BUCKET_URL}${filename}`;

export default api;
