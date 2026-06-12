# DeXray // GenAI-Powered APK Malware Analysis Platform

DeXray is a unified security intelligence and threat hunting dashboard designed for next-generation mobile security teams. It blends low-level **Static Heuristics** with **GenAI Semantic Interpretation** to analyze Android binaries (`.apk` files) for credential harvesting overlays, background SMS interception, and evasive command-and-control (C2) behaviors.

---

## Key Features

* **Resilient APK Disassembly & Decompilation**:

  * Utilizes `Androguard` to cleanly unpack the binary structure, packages, intents, and services.
  * Dynamically falls back to raw zip-level byte extraction and `classes.dex` scanning if the APK is obfuscated or packed.

* **GenAI Semantic Core**:

  * Integrated with the modern `google-genai` SDK using `gemini-2.5-flash` to perform semantic code analysis on suspicious Smali bytecode blocks.
  * Maps findings to active threat scenarios and identifies critical tactics.
  * Robust exception handling with an offline, high-fidelity local heuristic AI engine to ensure 100% stability.

* **Behavior Analysis Engine**:

  * Reuses extracted permissions, suspicious Smali snippets, and DEX/raw string signals to infer attacker behaviors such as SMS interception, overlay abuse, accessibility abuse, boot persistence, reflection usage, and dynamic loading.
  * Produces a consolidated `behavior_analysis` object and `behavior_score` to support semantic risk assessment.

* **Mathematical Risk Engine**:

  * Calculates threat severity score based on a rigorous mathematical formula accounting for base permission values, structural code indicators, behavior signal strength, and GenAI multiplier certainty.

* **Premium SOC Command Panel**:

  * Visual interactive **Risk Gauge** scaling dynamically with threat severity.
  * Tab-based navigation detailing executive risk reports, Android permission profiles, service intents, and raw Smali snippets.
  * Real-time automated SOC SIEM/SOAR incident response webhook simulation.

---

## Mathematical Risk Scoring Formula

DeXray determines the risk score using the following deterministic formula:

$$
\text{Risk Score} = \min(100.0, (\text{Permission Base Score} + \text{Structural Anomalies Score} + \text{Behavior Score}) \times \mu_{\text{AI}})
$$

Where:

* **Permission Base Score**:

  * `+15` points for each SMS intercept permission (`RECEIVE_SMS`, `READ_SMS`).
  * `+25` points for accessibility service binding (`BIND_ACCESSIBILITY_SERVICE`).

* **Structural Anomalies Score**:

  * `+10` points for each matching binary signature (e.g. plaintext HTTP C2 IP configs, WindowManager overlays, Telegram bots, or accessibility keylogger hooks).

* **AI Confidence Multiplier ($\mu_{\text{AI}}$)**:

  * Floating-point multiplier between `1.0` and `1.5` calculated dynamically by Gemini based on semantic code alignment with malware templates.

---

## Project Structure

```text
DeXray/
├── app.py                # Streamlit Frontend, Custom CSS Themes & Gauge SVG
├── analyzer.py           # Core decompilation, signature sieve, scoring & Gemini Client
├── requirements.txt      # Project library configuration
├── .env                  # Environment secrets for the Gemini API Key
└── README.md             # Project documentation
```

---

## Getting Started

### 1. Prerequisites

Ensure you have Python 3.10+ installed.

### 2. Install Dependencies

Install all required libraries from the requirements file:

```bash
pip install -r requirements.txt
```

### 3. Setup Gemini API Key

You can manage your credentials using either standard environment files or Streamlit's secrets management:

* **Option A: Streamlit Secrets (Recommended for Streamlit Cloud deployment)**

Create a `.streamlit/secrets.toml` file in the root directory and add the following entry:

```toml
GEMINI_API_KEY = "your_api_key_here"
```

*(Note: This file is ignored by git and should not be committed to your repository).*

* **Option B: Environment Configuration**

Create a `.env` file in the root directory:

```env
GEMINI_API_KEY=your_api_key_here
```

*(If no key is configured, DeXray will fall back to the offline mock analyzer).*

### 4. Run the Platform

Start the local Streamlit dashboard:

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## Interactive Presentation Sandbox

For live demonstrations and mock presentations, DeXray includes a sandbox containing preset profiles of notable banking trojan variants:

* **TeaBot (Anatsa)**: Demonstrates SMS interception, accessibility keylogging events, and Telegram API C2 communication channels.

* **Anubis V2**: Highlights dynamic login overlays, boot persistence loops, and plaintext socket calls.
