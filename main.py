from os import environ
import dotenv

from virus_total import scan_file, get_report_last_scan, print_report_file
from virus_total import scan_url, get_report, print_report_url
from virus_total import scan_ip, dump_to_json


if __name__ == "__main__":
	dotenv.load_dotenv('.env')
	key = environ["vt_api"]
	deteccted_only = True

	print("VIrus Total:\n 1) scan file\n 2) scan url\n 3) scan IP\n<any button> cencel\n")
	action = input("enter action:>")
	if action == "1":
		filename = input("Enter a 'file path' :>")
		scan_info = scan_file(filename, key)
		sing = scan_info.get("scan_id")
		report = get_report_last_scan(sing, key)
		print_report_file(report, detected_only=deteccted_only)
		report_file = "report_files.json"
		dump_to_json(report, report_file)
		print(f"Отчёт был сброшен в файл '{report_file}'")
	elif action == "2":
		url = input("Enter URL :>")
		report_dict = get_report(url, key)
		print_report_url(report_dict, detected_only=deteccted_only)
		report_file = "report_urls.json"
		dump_to_json(report_dict, report_file)
		print(f"Отчёт был сброшен в файл '{report_file}'")
	elif action == "3":
		ip = input("Enter IP :>")
		report = scan_ip(ip, apikey=key)
		report_file = "report_ips.json"
		dump_to_json(report, report_file)
		print(f"Отчёт был сброшен в файл '{report_file}'")
	else:
		print("Aaction canceled")




