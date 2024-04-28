# Nes_Pars

## Description
Parse Nessus XML files and generate reports.

## How to Run
1. Clone this repository to your local machine.
2. Navigate to the repository directory.

### Install Dependencies
- Python 3.x

You need to install the following Python libraries:
- `matplotlib`
- `lxml`
- `python-docx`

You can install the required libraries using pip:
`bash pip install matplotlib lxml python-docx`

## Usage
Run the script with the following command:
`python nessus_report_generator.py <file_path> <option>`

Replace <file_path> with the path to the Nessus XML file to parse, and <option> with one of the following report options:
1.'1': Full report
2.'2': Overview
3.'3': Per host
4.'4': Remediations

Example:
`python nessus_report_generator.py sample.nessus 1`

## Output
The script generates a Word document report based on the specified options.

## Additional Notes
The script will create a Word document named Nessus_Report_<option>.docx in the current directory.
The pie chart and any temporary files created during the report generation process will be automatically removed.
It's recommended to review and clean the input Nessus XML file before generating the report to ensure accurate results.
For large Nessus XML files, the report generation process may take some time. Be patient while the script processes the data.
Structure
nessus_report_generator.py: The main Python script for generating the report.
sample.nessus: Example Nessus XML file for testing purposes.
LICENSE: License file for the repository.
README.md: Readme file providing instructions and information about the script.
Contributing
Contributions are welcome! If you have suggestions, improvements, or bug fixes, please open an issue or create a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
