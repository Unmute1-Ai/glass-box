---
title: U1 Glass Box Public Test Lab
emoji: 🔬
colorFrom: blue
colorTo: indigo
sdk: gradio
app_file: app.py
python_version: 3.10
pinned: false
---

# U1 Glass Box Public Test Lab

A public, reproducible runner for the frozen U1 Control-Plane Evidence v2.7 package.

The app checks out a pinned source commit and runs either the four self-tests or the complete release verifier. It uses no live model, production endpoint, credentials, or real user data.

Read the claims boundary before interpreting results:
https://github.com/Unmute1-Ai/glass-box/blob/6f69ff051cc6ef67363cfe4fbb944c93b4a7da22/v2.7-reproducible/CLAIMS.md

This is a synthetic benchmark reproduction interface, not a security certification.

## Performance Monitoring

This app includes Vercel Speed Insights integration for performance monitoring. The Speed Insights initialization script is embedded in the application and will automatically track Core Web Vitals and performance metrics when the app is deployed on Vercel's platform.

**Note:** Speed Insights data collection only works when deployed to Vercel. It will not collect metrics during local development or when hosted on other platforms (like Hugging Face Spaces) unless configured with a custom endpoint.
