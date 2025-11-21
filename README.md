```markdown
# TasksParser

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)

A modern Windows Task Scheduler analyzer that detects suspicious scheduled tasks with a beautiful glass-morphism interface.

## 🚀 Features

- **Comprehensive Scanning** - Analyzes all Windows Task Scheduler tasks and folders
- **Advanced Detection** - Identifies Proxy Execution and GhostTask persistence
- **Modern UI** - Glass-morphism interface with real-time progress tracking
- **Smart Filtering** - Search and filter results by multiple criteria
- **Signature Verification** - Checks digital signatures of executable files

## 🛡️ Detection Capabilities

| Detection Type | Description |
|---------------|-------------|
| **Proxy Execution** | Detects when system executables are used to run other suspicious files |
| **GhostTask Persistence** | Identifies registry-only tasks without XML files (Registry Mismatch) |

## 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ritzysixx/TasksParser.git
   cd TasksParser
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## 🎯 Usage

Run the application:
```bash
python TasksParser.py
```

### Interface Controls
- **Scan Tasks** - Start analyzing all scheduled tasks
- **Stop Scan** - Cancel ongoing scan
- **Clear Results** - Reset the results grid
- **Search** - Filter tasks by name, path, or arguments
- **Toggle Filters** - Show only unsigned, on-logon, flagged, or deleted tasks

### Quick Actions
- **Click** any cell to select
- **Right-click** or **Shift+Click** to copy cell content
- **Drag** the title bar to move the window

## 🖥️ Interface Preview

The application features a modern glass-morphism design with:
- Real-time progress tracking
- Interactive results grid
- Advanced filtering options
- Copy-to-clipboard functionality

## 🔧 Technical Details

- Built with Python and pywebview
- Uses Windows Task Scheduler COM API
- Implements digital signature verification
- Multi-threaded scanning for performance
- Registry analysis for persistence detection

## 📋 Requirements

- Windows 7 or newer
- Python 3.7+
- Required packages: `pywebview`, `pywin32`

## 🐛 Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/ritzysixx/TasksParser/issues).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Use responsibly and only on systems you own or have permission to test.
