# Graph Zero-Day Detection

A starter Python project for simulating graph-based cyber activity, detecting zero-day-like anomalies, and producing containment actions.

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the CLI simulation:

   ```bash
   python main.py
   ```

4. Run the dashboard:

   ```bash
   streamlit run dashboard/app.py
   ```

## Project Structure

- `simulation/`: Graph and attack simulation utilities.
- `detection/`: Anomaly detection logic.
- `containment/`: Response and containment strategy generation.
- `dashboard/`: Streamlit UI for viewing detections and actions.
- `data/sample/`: Sample data storage.
- `tests/`: Automated tests.
- `docs/`: Documentation.
