import os
import subprocess
import shutil
import zipfile
import hashlib
import logging

# Set up logging
logging.basicConfig(filename='forensic_tool.log', level=logging.INFO)

def collect_evidence(output_dir):
    # Create a directory to store the collected evidence
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Collect system information
    subprocess.run(['systeminfo'], stdout=open(os.path.join(output_dir, 'systeminfo.txt'), 'w'))

    # Collect running processes
    subprocess.run(['tasklist'], stdout=open(os.path.join(output_dir, 'tasklist.txt'), 'w'))

    # Collect network information
    subprocess.run(['ipconfig', '/all'], stdout=open(os.path.join(output_dir, 'ipconfig.txt'), 'w'))

    # Collect event logs
    subprocess.run(['wevtutil', 'epl', 'System', os.path.join(output_dir, 'system.evtx')])
    subprocess.run(['wevtutil', 'epl', 'Security', os.path.join(output_dir, 'security.evtx')])
    subprocess.run(['wevtutil', 'epl', 'Application', os.path.join(output_dir, 'application.evtx')])

def analyze_evidence(output_dir):
    # Analyze collected evidence
    hash_results = {}
    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'rb') as file:
                file_hash = hashlib.sha256(file.read()).hexdigest()
                hash_results[filename] = file_hash
    return hash_results

def create_report(output_dir, hash_results):
    # Create a report
    with open(os.path.join(output_dir, 'report.txt'), 'w') as report_file:
        report_file.write('Evidence Analysis Report\n\n')
        for filename, file_hash in hash_results.items():
            report_file.write(f'{filename}: {file_hash}\n')

def archive_output(output_dir, output_zip):
    # Archive the output directory
    with zipfile.ZipFile(output_zip, 'w') as zipf:
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), output_dir))

if __name__ == '__main__':
    output_dir = 'forensic_output'
    output_zip = 'forensic_output.zip'

    try:
        collect_evidence(output_dir)
        logging.info('Evidence collection successful')

        hash_results = analyze_evidence(output_dir)
        logging.info('Evidence analysis successful')

        create_report(output_dir, hash_results)
        logging.info('Report creation successful')

        archive_output(output_dir, output_zip)
        logging.info('Output directory archived successfully')

    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
