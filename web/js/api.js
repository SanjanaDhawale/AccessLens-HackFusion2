"use strict";

window.AccessLensAPI = {
  baseUrl() {
    return window.ACCESSLENS_CONFIG.API_BASE_URL.replace(/\/$/, "");
  },

  async request(path, options = {}) {
    const response = await fetch(this.baseUrl() + path, {
      ...options,
      headers: {
        ...(!(options.body instanceof FormData)
          ? { "Content-Type": "application/json" }
          : {}),
        ...(options.headers || {})
      }
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    if (response.status === 204) return null;
    return response.json();
  },

  health() {
    return this.request("/health");
  },

  registerTarget(data) {
    return this.request("/targets", {
      method: "POST",
      body: JSON.stringify(data)
    });
  },

  uploadSpecification(formData) {
    return this.request("/targets/specification", {
      method: "POST",
      body: formData
    });
  },

  startScan(data) {
    return this.request("/scans", {
      method: "POST",
      body: JSON.stringify(data)
    });
  },

  scanStatus(id) {
    return this.request(`/scans/${encodeURIComponent(id)}`);
  },

  endpoints(id) {
    return this.request(`/scans/${encodeURIComponent(id)}/endpoints`);
  },

  findings(id) {
    return this.request(`/scans/${encodeURIComponent(id)}/findings`);
  },

  evidence(id) {
    return this.request(`/scans/${encodeURIComponent(id)}/evidence`);
  },

  generateReport(id) {
    return this.request(`/reports/${encodeURIComponent(id)}`, {
      method: "POST"
    });
  },

  reportDownloadUrl(id) {
    return this.baseUrl() +
      `/reports/${encodeURIComponent(id)}/download`;
  }
};
