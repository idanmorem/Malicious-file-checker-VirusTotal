import argparse
import json
from typing import Tuple

import requests

API_KEY = "07f4699747601ed1b285bec4163f68bd8440b1a9fea0382546cf3009616f68b8"


def malicious_file_checker(file_hash: str, extract_file: bool) -> str:
    data = get_data(file_hash)
    data_json = json.loads(data.text)
    sha1 = data_json['data']['attributes']['sha1']
    sha256 = data_json['data']['attributes']['sha256']
    md5 = data_json['data']['attributes']['md5']
    total_scans = sum(data_json['data']['attributes']['last_analysis_stats'].values())
    malicious_scans = data_json['data']['attributes']['last_analysis_stats']['malicious']
    last_analysis_results = data_json['data']['attributes']['last_analysis_results']

    markdown = (
        "**File information**"
        "\n\n"
        "| MD5 | SHA-1 | SHA-256 |\n"
        "|---------|--------|------|\n"
        f"|    {md5}   |{sha1}|{sha256}|\n"
        "\n"
        "**Last analysis status**\n\n"
        "| Total scans | Malicious scans |\n"
        "|----------|-----------|\n"
        f"|  {total_scans} | {malicious_scans} | \n"
        "\n"
        "**Last analysis results**\n\n"
        "| Scan origin | Scan results |\n"
        "|----------|-----------|\n"
    ).format(md5=md5,
             sha1=sha1, sha256=sha256,
             total_scans=total_scans,
             malicious_scans=malicious_scans)

    for scan in last_analysis_results.keys():
        scan = last_analysis_results[scan]
        name = scan['engine_name']
        category = scan['category']
        markdown += f"|  {name} | {category} | \n".format(name=name, category=category)
    if extract_file:
        with open("mark.md", "w") as file:
            file.write(markdown)

    return markdown


def get_data(filesHash: str) -> requests.Response:
    url = f"https://www.virustotal.com/api/v3/files/{filesHash}"

    headers = {"Accept": "application/json",
               "X-Apikey": API_KEY}

    return requests.get(url, headers=headers)


def cli_arguments_reader() -> Tuple[str, bool]:
    parser = argparse.ArgumentParser(description='malicious file checker')
    parser.add_argument('fileHash', type=str,
                        help='A hash authenticator for specific file')
    parser.add_argument('--extractToFile', type=bool, default=False,
                        help='Feature flag to extract the markdown table to a file (mark.md)')

    return parser.parse_args().fileHash, parser.parse_args().extractToFile


if __name__ == '__main__':
    arguments = cli_arguments_reader()
    malicious_file_checker(file_hash=arguments[0], extract_file=arguments[1])
