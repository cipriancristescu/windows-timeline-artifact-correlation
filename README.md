# Windows Timeline Artifact Correlation

A Python tool for reconstructing and correlating Windows activity timelines from forensic artifact exports. The project supports both a command-line workflow and a Streamlit interface.

## Features

- Parses Browser History, Prefetch, and MFT CSV exports.
- Normalizes heterogeneous artifact records into a common event model.
- Filters, groups, and correlates events using deterministic rules.
- Provides a Streamlit interface for interactive analysis.
- Exports selected findings for reporting.
- Includes automated tests for parsers, normalization, filtering, correlation, and export behavior.

## Repository Structure

```text
app.py              Streamlit application
main.py             CLI entry point
config/             Application configuration
src/                Core implementation
tests/              Automated tests
requirements.txt    Python dependencies
```

Raw forensic data, experiment outputs, and thesis documentation are intentionally not included in this repository.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run the Streamlit Interface

```powershell
streamlit run app.py
```

## Run the CLI

```powershell
python main.py --input path\to\input --output path\to\output
```

The input directory should contain the exported artifact files expected by the parsers. Generated outputs should be written outside the tracked source tree or inside an ignored output directory.

## Run Tests

```powershell
pytest
```

## Data Availability

This repository does not include raw forensic artifacts because they may be large or sensitive. Reproducibility data can be provided separately, for example through a dedicated data repository, an archive link, or a download script referenced from this section.

## Configuration

Default settings are stored in `config/app_config.yaml`. AI-assisted analysis is optional and configured separately from the deterministic parsing, grouping, and correlation pipeline.

## Reproducibility Notes

For thesis reproduction, document the following together with the experiment data source:

- operating system and version;
- Python version;
- hardware used for experiments;
- artifact export method;
- exact commands used for setup, execution, and testing.
