# TasksParser

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge)

A modern Windows Task Scheduler analyzer that detects suspicious scheduled tasks with an enhanced glass-morphism interface.

## 🚀 What's New in v2.0.0

### ✨ Enhanced UI/UX
- **Premium Glass-Morphism Design** - Completely revamped interface with advanced visual effects
- **Expanded Grid Layout** - New columns for arguments, on-logon status, and detection flags
- **Smoother Animations** - Enhanced transitions and hover effects throughout
- **Advanced Filtering** - Multiple toggle filters for precise task analysis

### 🔧 Technical Improvements
- **Optimized Performance** - Multi-threaded scanning with ThreadPoolExecutor (8 workers)
- **Enhanced Detection** - Improved Proxy Execution and GhostTask persistence detection
- **Better Path Resolution** - Advanced executable path extraction from commands and arguments
- **Robust Signature Verification** - Dual verification with WinVerifyTrust and catalog signing

### 🛡️ New Detection Capabilities
- **Proxy Execution Detection** - Identifies system binaries used to launch suspicious payloads
- **GhostTask Persistence** - Detects registry-only tasks without XML files
- **On-Logon Analysis** - Flags tasks configured to run at user logon
- **Argument Analysis** - Examines command-line arguments for suspicious patterns

## 📊 Detection Matrix

| Detection Type | Icon | Description |
|---------------|------|-------------|
| **Proxy Execution** | 🟡 | System executables used to run suspicious files |
| **GhostTask Persistence** | 🔴 | Registry-only tasks without XML files |
| **On-Logon Execution** | ⚠️ | Tasks configured to run at user logon |
| **Unsigned Executables** | 🟠 | Files without valid digital signatures |
| **Deleted Files** | 🔴 | Referenced executables that no longer exist |

## 📦 Installation

### Option 1: Using Pre-built Executable (Recommended)
1. Download the latest `TasksParser.exe` from [Releases](https://github.com/ritzysixx/TasksParser/releases)
2. Run `TasksParser.exe` directly - no installation required!

### Option 2: Build from Source
1. **Clone the repository**
   ```bash
   git clone https://github.com/ritzysixx/TasksParser.git
   cd TasksParser
   ```

2. **Install Python dependencies**
   ```bash
   pip install pywebview pywin32
   ```

3. **Run the application**
   ```bash
   python TasksParser.py
   ```

### Option 3: Build Executable
```bash
pip install pyinstaller
python -m PyInstaller --onefile --windowed --add-data "web;web" --hidden-import="webview" --hidden-import="webview.platforms.win32" TasksParser.py
```

## 🎯 Usage

### Quick Start
1. **Launch**: Run TasksParser.exe
2. **Scan**: Click "Scan Tasks" to analyze all Windows scheduled tasks
3. **Review**: Examine results with color-coded detection flags
4. **Filter**: Use search and toggle filters to focus on suspicious tasks

### Interface Controls
- **Scan Tasks** - Comprehensive analysis of all scheduled tasks
- **Stop Scan** - Cancel ongoing scan operation
- **Clear Results** - Reset the results grid
- **Search Bar** - Real-time filtering by task name, path, arguments, or detections
- **Toggle Filters** - Filter by: Unsigned, On Logon, Flagged, Has Arguments, Deleted

### Advanced Features
- **Quick Copy**: Right-click or Shift+Click any cell to copy content
- **Drag Window**: Click and drag title bar to move the frameless window
- **Real-time Progress**: Live progress tracking during scanning
- **Detailed Analysis**: View executable paths, arguments, and detection reasons

## 🖥️ Interface Preview

The v2.0.0 interface features:
- **Expanded Grid View** - 6-column layout showing comprehensive task details
- **Visual Indicators** - Color-coded status for signatures and on-logon execution
- **Detection Flags** - Badge-style indicators for security findings
- **Premium Styling** - Enhanced glass effects with backdrop filters
- **Responsive Design** - Optimized for various screen sizes

## 🔧 Technical Details

### Backend Architecture
- **Python Core** - Robust analysis engine with Windows API integration
- **Task Scheduler COM** - Direct integration with Windows Task Scheduler
- **Multi-threading** - Concurrent processing with 8 worker threads
- **Registry Analysis** - Comprehensive registry scanning for persistence detection

### Detection Engine
- **Proxy Execution** - Analyzes system binary usage patterns
- **GhostTask Detection** - Compares registry entries with Task Scheduler database
- **Signature Verification** - Dual-check system using WinVerifyTrust and catalog signing
- **Path Resolution** - Smart extraction of executable paths from commands and arguments

### Security Analysis
- **XML Parsing** - Detailed analysis of task definitions and triggers
- **Pattern Matching** - Advanced regex for command and argument analysis
- **Environment Resolution** - Proper handling of environment variables and system paths
- **Error Resilience** - Robust error handling for inaccessible tasks

## 📋 System Requirements

- **OS**: Windows 7 or newer
- **Architecture**: x64 or x86
- **RAM**: 2GB minimum (4GB recommended)
- **Storage**: 50MB free space
- **Permissions**: Administrator rights recommended for full system access

## 🐛 Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/ritzysixx/TasksParser/issues) with:
- Detailed description of the problem
- Steps to reproduce
- Screenshots (if applicable)
- Your system specifications

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for legitimate security analysis, digital forensics, and system administration purposes. Users are responsible for complying with local laws and regulations regarding system analysis. Use only on systems you own or have explicit permission to test.
