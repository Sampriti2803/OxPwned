# OxPwned - Hybrid Malware Detection and Trend Analysis System

### Overview

OxPwned is a hybrid malware detection system designed for the banking sector. By combining the strengths of signature-based detection and machine learning, it delivers comprehensive protection against both known and zero-day threats. This project was developed as part of PNB's Cybersecurity Hackathon-2024.

---

## Features

- **Dual-Layer Detection**: Combines YARA rules and ClamAV for signature-based detection with machine learning models (TensorFlow or PyTorch) for behavioral analysis.
- **Real-Time Alerts**: Provides instant notifications and detailed logs for rapid response.
- **Sandbox Testing**: Leverages Docker for secure and isolated testing of threats.
- **Scalability**: Supports large datasets and evolving malware, with future-proof modular architecture.
- **Resource-Efficient**: Optimized for minimal CPU and RAM usage.

---

## Technical Implementation

### Tools and Technologies

- **Machine Learning**: TensorFlow or PyTorch for detecting unknown malware.
- **Signature Matching**: YARA rules and ClamAV for known threats.
- **Monitoring**: ELK Stack for real-time visualization and alerts.
- **Sandboxing**: Docker for secure testing environments.

### Workflow

1. **Input Layer**: Scans files and monitors network traffic.
2. **Processing Layer**:
   - Matches known threats using signature-based methods.
   - Analyzes behavior of unmatched data with ML models.
3. **Output Layer**: Sends alerts and logs to Security Operations Center (SOC) teams.

### Dataflow

```plaintext
OxPwned/
├── LICENSE
├── README.md
├── admin/
│   ├── communication/
│   │   ├── receiver.py
│   │   └── utils.py
│   ├── main.py
│   ├── ml/
│   │   └── models/
│   │       ├── predictor.py
│   │       ├── trained_model/
│   │       ├── trainer.py
│   │       ├── training_data/
│   │       └── utils.py
│   ├── monitoring/
│   │   ├── elk_stack/
│   │   └── logger.py
│   ├── reports/
│   │   ├── alerts/
│   │   └── historical/
│   ├── sandbox/
│   │   ├── docker_files/
│   │   └── test_env_setup.py
│   ├── signature_based/
│   │   ├── scanner.py
│   │   ├── signatures/
│   │   │   ├── clamav/
│   │   │   └── yara/
│   │   └── updater.py
│   └── tests/
│       ├── integration/
│       └── unit/
├── configs/
│   ├── admin_config.yaml
│   ├── logging_config.yaml
│   └── terminal_config.yaml
├── docs/
│   ├── architecture.md
│   ├── requirements.md
│   └── user_guide.md
├── logs/
│   ├── admin/
│   └── terminal/
├── requirements.txt
├── scripts/
│   ├── deployment/
│   │   ├── deploy_admin.sh
│   │   ├── deploy_terminal.sh
│   │   └── rollback.sh
│   ├── setup/
│   │   ├── setup_admin.sh
│   │   └── setup_terminal.sh
│   └── testing/
│       ├── coverage.sh
│       ├── run_tests_admin.sh
│       ├── run_tests_terminal.sh
├── shared/
│   ├── interfaces/
│   │   ├── shared_data_schema.json
│   │   └── terminal_to_admin.py
│   └── utils/
│       ├── data_serializer.py
│       ├── network_utilities.py
│       └── threat_levels.py
├── terminal/
│   ├── communication/
│   │   ├── sender.py
│   │   └── utils.py
│   ├── detection/
│   │   ├── pattern_match/
│   │   │   ├── engine.py
│   │   │   ├── heuristic.py
│   │   │   ├── matcher.py
│   │   │   ├── rules/
│   │   │   │   ├── regex_patterns/
│   │   │   │   │   ├── akira_patterns.json
│   │   │   │   │   ├── lockbit_patterns.json
│   │   │   │   │   └── suspicious_traffic_patterns.json
│   │   │   │   └── yara_rules/
│   │   │   ├── threat_intelligence/
│   │   │   │   ├── domain_blacklist.json
│   │   │   │   ├── hashes.json
│   │   │   │   └── ip_blacklist.json
│   │   │   └── utils.py
│   │   └── preprocessing/
│   │       ├── data_cleaner.py
│   │       ├── feature_extractor.py
│   │       ├── network_parser.py
│   │       └── test.py
│   ├── main.py
│   ├── output/
│   │   ├── alerts/
│   │   └── logs/
│   └── tests/
│       ├── integration/
│       └── unit/
└── tests/
    ├── admin/
    ├── shared/
    └── terminal/
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Docker
- TensorFlow or PyTorch
- ELK Stack (Elasticsearch, Logstash, Kibana)
- ClamAV, YARA

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-repo/OxPwned.git
   cd OxPwned
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure the system:

- Edit configs/admin_config.yaml for admin configurations.
- Adjust logging parameters in logging_config.yaml.

4. Run setup scripts:

   ```bash
   bash scripts/setup/setup_admin.sh
   bash scripts/setup/setup_terminal.sh
   ```

---

## Usage

### Admin Console

1. Start the admin console:

```bash
python admin/main.py
```

2. Monitor logs and alerts under logs/admin/.

### Terminal Console

1. Launch the terminal console:

```bash
python terminal/main.py
```

2. Access threat intelligence outputs under terminal/output/alerts/.

---

## Documentation

For detailed architecture and implementation, refer to:

- docs/architecture.md
- docs/requirements.md
- docs/user_guide.md

---

## Contributors

- [Pranav Hemanth](https://github.com/Pranavh-2004)
- [Sampriti Saha](https://github.com/Sampriti2803)
- [Pranav Rajesh Narayan](https://github.com/pranav-rn)
- [Kshitij Kota](https://github.com/kshitijkota)
- [Roshini Ramesh](https://github.com/roshr22)

---

## Contributions

Contributions are welcome! Please refer to docs/user_guide.md for guidelines.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Acknowledgments

- PNB Cybersecurity Hackathon-2024 initiative.
- Open-source tools and frameworks: TensorFlow, PyTorch, YARA, ClamAV, Docker, and ELK Stack.
