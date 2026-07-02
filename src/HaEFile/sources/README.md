<div align="center">
<h3><a href="https://github.com/gh0stkey/HaE">HaE File</a></h3>
<h5>First Author: <a href="https://github.com/0chencc">0chencc</a> (Mystery Security Team)<br>Second Author: <a href="https://github.com/gh0stkey">EvilChen</a></h5>
</div>

Thank you list for the beta pioneer program: 冰淇霖, ArG3, Kite

## Project Introduction

By utilizing **regex engine** customized expressions, HaE File can accurately match and process file contents, effectively tagging and extracting information from successfully matched content. This enhances the **efficiency of vulnerability and data analysis** in the field of cybersecurity (data security).

> The volume of logs, configuration files, and source code that need to be processed during daily analysis is growing rapidly. Relying solely on traditional text tools for manual inspection often consumes significant effort on irrelevant content. **The emergence of HaE File aims to address such situations** — with HaE File, you can precisely filter out redundant information and focus more effort on content that matches key characteristics, thereby **improving the efficiency of vulnerability and data analysis**.

## Usage

1. Install the HaE extension in VS Code (`Extensions` -> `Install from VSIX...`).
2. Run scans via the right-click context menu or the HaE Databoard panel:
   - **Scan File** — Scan a specific file
   - **Scan Folder** — Scan a specific folder
   - **Scan Workspace** — Scan the entire workspace
3. Scan results will be displayed in the **Databoard** data panel in the sidebar. Click on a rule to view match details.
4. When a file is opened, the bottom **File Inspector** panel will display real-time match information for the current file.
5. Matched content in the editor is automatically highlighted (can be disabled in settings).