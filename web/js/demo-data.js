"use strict";

// Synthetic frontend demonstration data. Never display as real scan results.
window.AccessLensDemo = {
  enabled: true,
  label: "DEMO DATA - NOT LIVE",
  source: "synthetic",
  scans: [{target:"api.example.test",status:"Completed",findings:5,date:"Oct 29, 2026"},{target:"shop.example.test",status:"Completed",findings:8,date:"Oct 28, 2026"},{target:"dev.example.test",status:"Running",findings:"—",date:"Oct 28, 2026"},{target:"auth.example.test",status:"Failed",findings:"—",date:"Oct 27, 2026"}],
  findings: [{endpoint:"GET /api/users/{id}",issue:"Broken Object Level Authorization",severity:"Critical",owasp:"API1:2023",status:"FAIL"},{endpoint:"POST /api/login",issue:"Broken Authentication",severity:"High",owasp:"API2:2023",status:"FAIL"},{endpoint:"GET /api/profile",issue:"Excessive Data Exposure",severity:"High",owasp:"API3:2023",status:"FAIL"},{endpoint:"GET /api/config",issue:"Security Misconfiguration",severity:"Medium",owasp:"API8:2023",status:"FAIL"}],
  sampleUsers: [{name:"Demo Admin",role:"Admin",status:"Active"},{name:"Demo Analyst",role:"Analyst",status:"Active"}],
  sampleLogs: [{event:"Scan created",actor:"Demo Analyst",date:"Oct 29, 2026"},{event:"Report generated",actor:"Demo Admin",date:"Oct 28, 2026"},{event:"Scope approved",actor:"Demo Analyst",date:"Oct 27, 2026"}]
};

