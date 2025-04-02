import axios from "axios";
import Cookies from "js-cookie";

const api = axios.create({
  baseURL: "https://api.trustforge.pro",
});

api.interceptors.request.use((config) => {
  const token = Cookies.get("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = Cookies.get("refreshToken");
      if (refreshToken) {
        try {
          // Attempt to refresh the access token
          const response = await axios.post(
            `${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`,
            {
              refreshToken,
            }
          );

          const newAccessToken = response.data.accessToken;
          const newRefreshToken = response.data.refreshToken;

          // Update cookies with the new tokens
          Cookies.set("token", newAccessToken);
          Cookies.set("refreshToken", newRefreshToken);

          // Retry the original request with the new access token
          error.config.headers.Authorization = `Bearer ${newAccessToken}`;
          return api.request(error.config);
        } catch (refreshError) {
          // If refresh fails, clear cookies and redirect to login
          Cookies.remove("token");
          Cookies.remove("refreshToken");
          Cookies.remove("user");
          window.location.href = "/login";
        }
      } else {
        // If no refresh token, clear cookies and redirect to login
        Cookies.remove("token");
        Cookies.remove("refreshToken");
        Cookies.remove("user");
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export const auth = {
  login: async (email: string, password: string) => {
    const response = await api.post("/auth/login", { email, password });
    const accessToken = response.data.session.access_token;
    const refreshToken = response.data.refreshToken;

    Cookies.set("token", accessToken);
    Cookies.set("refreshToken", refreshToken);
    Cookies.set("user", JSON.stringify(response.data.user));

    return response.data;
  },
  register: async (email: string, password: string) => {
    const response = await api.post("/auth/register", { email, password });
    return response.data;
  },
  logout: () => {
    Cookies.remove("token");
    Cookies.remove("refreshToken");
    Cookies.remove("user");
    window.location.href = "/login";
  },
};

export const dashboard = {
  getStats: async () => {
    const response = await api.get("/dashboard");
    return response.data;
  },
};

export const scan = {
  upload: async (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    const response = await api.post("/scan/upload", formData);
    return response.data;
  },
  getStatus: async (scanId: string) => {
    const response = await api.get(`/scan/status/${scanId}`);
    return response.data;
  },
  getReport: async (scanId: string) => {
    const response = await api.get(`/report/${scanId}`);
    return response.data;
  },
  getAllReports: async (page: number = 1, limit: number = 5) => {
    const response = await api.get(`/report/`, {
      params: { page, limit },
    });
    return response.data;
  },
  deleteReport: async (scanId: string) => {
    const response = await api.delete(`/report/${scanId}`);
    return response.data;
  },
};

export default api;
