from os import environ
import os.path
import dotenv
import json
import requests

def scan_file(filename:str, api_key:str) -> dict:
	api_url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
	params = dict(apikey=api_key)
	info_dict = dict()
	if os.path.exists(filename):
		with open(filename, 'rb') as file:
			files = dict(file=(filename, file))
			response = requests.post(api_url_scan, files=files, params=params, timeout=15)
		if response.status_code == 200:
			result = response.json()
			info_str = json.dumps(result, sort_keys=False, indent=4)
			info_dict = json.loads(info_str)
	else:
		print("File not exist:")
		exit(1)
	return info_dict


def get_report_last_scan(sing:str, api_key:str) -> dict:
	api_url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
	params = dict(apikey=api_key, resource=sing)
	response = requests.get(api_url_report, params=params, timeout=15)
	report = ""
	if response.status_code == 200:
		result = response.json()
		report = json.dumps(result, sort_keys=False, indent=4)
	else:
		print("Что-то пошло не так...")
		exit(1)
	return json.loads(report)


def print_report_from_dict(report: dict):

	print("INFO:")
	print("   scan_id: ", report["scan_id"])
	print("   total: ", report["total"])
	print("   positives: ", report["positives"])
	print("   permalink: ", report["permalink"])
	print("   scan_date: ", report["scan_date"])
	print("   response_code: ", report["response_code"])
	print("   verbose_msg: ", report["verbose_msg"])

	print("\nHash sum:")
	print("  sha1: ", report['sha1'])
	print("  sha256: ", report["sha256"])
	print("  md5: ", report["md5"])

	print("\nSCANS:")
	for key in report['scans']:
		print(key)
		print("   Detected", report['scans'][key]['detected'])
		print("   Version: ", report['scans'][key]['version'])
		print("   Result: ", report['scans'][key]['result'])
		print("   Update: ", report['scans'][key]['update'])



if __name__ == "__main__":
	dotenv.load_dotenv('.env')
	key = environ["vt_api"]
	filename = input("Enter a 'file path' :>")

	scan_info = scan_file(filename, key)
	sing = scan_info['scan_id']
	report = get_report_last_scan(sing, key)
	#print(report)
	print_report_from_dict(report)



