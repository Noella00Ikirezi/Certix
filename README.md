# Certix

# ISO 27001 Annex A Audit Console

A comprehensive security audit tool built with PySide6 for auditing Windows and Linux systems against ISO 27001 Annex A controls.

## Features

- **Dual OS Support**: Audit both Windows and Linux systems
- **ISO 27001 Annex A Controls**: Covers 14 key security controls including:
  - A.5.1: Policies for information security
  - A.5.2: Information security roles
  - A.8.1: User access management
  - A.8.2: User access provisioning
  - A.8.3: Privileged access rights
  - A.8.5: Secure authentication
  - A.8.8: Management of technical vulnerabilities
  - A.8.9: Configuration management
  - A.8.10: Information deletion
  - A.8.15: Logging
  - A.8.16: Monitoring activities
  - A.8.18: Use of privileged utility programs
  - A.8.23: Web filtering
  - A.8.26: Application security requirements

- **Modern GUI**: Clean, intuitive interface with multiple views
- **Real-time Progress**: Visual feedback during audit execution
- **Multiple Report Views**: 
  - Summary dashboard
  - Detailed results table
  - Raw JSON output
- **Export Capability**: Export audit results to JSON format
- **Console Logging**: Real-time console output for debugging

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install PySide6 directly:

```bash
pip install PySide6
```

## Usage

### Running the Application

```bash
python iso27001_audit_console.py
```

### Using the Console

1. **Select Target OS**: Choose between Windows or Linux from the dropdown
2. **Start Audit**: Click "Start Audit" to begin the security assessment
3. **Monitor Progress**: Watch the progress bar and console output
4. **Review Results**: Check the Summary, Detailed Results, and Raw Output tabs
5. **Export Report**: Save the audit results as a JSON file for documentation

### Understanding Results

The audit assigns the following statuses:

- **PASS** (Green): Control is properly implemented
- **FAIL** (Red): Control has failed or is not implemented
- **WARN** (Orange): Control has warnings or potential issues
- **INFO** (Blue): Control requires manual review
- **ERROR** (Dark Red): Error occurred during check

## Windows-Specific Checks

The Windows audit performs checks using:
- `secedit` - Security policy export
- `net` commands - User and group enumeration
- `wmic` - Updates and installed software
- `wevtutil` - Event log configuration

### Recommended Privileges

Run as Administrator for complete audit results.

## Linux-Specific Checks

The Linux audit performs checks using:
- `getenforce`, `aa-status` - Security framework status
- `getent` - User and group information
- PAM configuration files
- Package manager queries (apt, yum, dnf)
- Log file verification

### Recommended Privileges

Run with sudo privileges for complete audit results:

```bash
sudo python iso27001_audit_console.py
```

## File Structure

```
iso27001_audit_console.py  # Main application
requirements.txt           # Python dependencies
README.md                  # This file
```

## Audit Report Structure

Exported JSON reports contain:
```json
{
  "timestamp": "2025-11-14T10:30:00",
  "os": "Linux",
  "controls": [
    {
      "id": "A.5.1",
      "name": "Policies for information security",
      "status": "PASS",
      "findings": ["Finding 1", "Finding 2"],
      "recommendations": []
    }
  ]
}
```

## Compliance Calculation

The compliance rate is calculated as:
```
Compliance % = (Number of PASS controls / Total controls) × 100
```

## Customization

### Adding New Controls

To add new ISO 27001 controls:

1. Add the control to the `controls` list in `audit_windows()` or `audit_linux()`
2. Create a corresponding check function (e.g., `check_windows_newcontrol()`)
3. Implement the audit logic in the check function
4. Return a dict with `status` and `findings`

### Example:

```python
def check_windows_custom(self) -> Dict:
    """Custom security check"""
    try:
        # Your audit logic here
        findings = ["Custom check result"]
        status = "PASS"
        return {"status": status, "findings": findings}
    except Exception as e:
        return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}
```

## Limitations

- Some checks require administrative/root privileges
- Network-related checks may need additional tools
- Results should be reviewed by security professionals
- This tool provides guidance, not certification

## Security Considerations

- The tool reads system configuration but does not modify anything
- Some commands may trigger security software alerts
- Review findings in context of your organization's policies
- Always test in a non-production environment first

## Troubleshooting

### "Permission Denied" Errors
- Run with elevated privileges (Administrator/sudo)

### "Command Not Found" Errors
- Some commands may not be available on all systems
- Install missing tools or review INFO status items manually

### GUI Not Loading
- Ensure PySide6 is properly installed
- Check Python version compatibility (3.8+)

## Best Practices

1. Run audits regularly (monthly/quarterly)
2. Document remediation actions for failed controls
3. Track compliance trends over time
4. Combine with manual security reviews
5. Export and archive audit reports

## Contributing

To extend this tool:
- Add new ISO 27001 controls
- Improve detection logic
- Add support for additional operating systems
- Enhance reporting capabilities

## License

This tool is provided as-is for educational and assessment purposes.

## Disclaimer

This audit tool is intended to assist with ISO 27001 compliance assessments but does not replace:
- Professional security audits
- Official ISO 27001 certification processes
- Expert security consultation
- Comprehensive penetration testing

Always consult with qualified security professionals for compliance and certification guidance.

## Support

For issues or questions:
- Review the console output for error messages
- Check system requirements
- Verify elevated privileges
- Ensure all dependencies are installed

## Version History

- **v1.0**: Initial release with Windows and Linux support
  - 14 ISO 27001 Annex A controls
  - Multi-tab results interface
  - JSON export capability
  - Real-time progress tracking