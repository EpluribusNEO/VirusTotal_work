from os import environ
import dotenv

from virus_total import scan_file, get_report_last_scan
from virus_total import print_report_from_dict_for_file as print_file_report
from virus_total import scan_url, get_report



if __name__ == "__main__":
	test_path = f"C:\Den\TRUSH\z.exe"
	test_url = f"https://xakep.ru/author/drobotun/"
	dotenv.load_dotenv('.env')
	key = environ["vt_api"]

	print("VIrus Total:\n 1) scan file\n 2) scan url\n<any button> cencel\n")
	action = input("enter action:>")
	if action == "1":
		filename = test_path #input("Enter a 'file path' :>")
		scan_info = scan_file(filename, key)
		sing = scan_info.get("scan_id")
		report = get_report_last_scan(sing, key)
		print_file_report(report, detected_only=False)
	elif action == "2":
		urlname = test_url #input("Enter URL :>")
		scan_url(urlname, key)
	else:
		print("Aaction canceled")




