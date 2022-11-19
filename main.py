from os import environ
import dotenv


if __name__ == "__main__":
	dotenv.load_dotenv('.env')
	key = environ["vt_api"]
