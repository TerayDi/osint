import configparser
import os

default_sections = ["AbuseIPDB", "VirusTotal"]
config_file_path = 'api.conf'
 

def check_api():
    try:
        conf = configparser.ConfigParser()
        print("Checking for config file...")
        # Leggi il file solo se esiste
        if os.path.exists(config_file_path):
            conf.read(config_file_path)
            conf_sections = conf.sections()
            
            # Verifica la presenza di sezioni
            if len(conf_sections) < 2:
                print("Follow next step to end configuration")
            else:
                print("Checking for api keys...")

            # Verifica e aggiunge le sezioni mancanti
            for section in default_sections:
                if section not in conf_sections:
                    # Aggiungi la sezione mancante
                    print(f'Missing {section} key')
                    api_key = input(f'Insert api key for {section}: ')
                    conf[section] = {"key": api_key}

            # Scrivi le modifiche nel file di configurazione
            with open(config_file_path, 'w') as configfile:
                conf.write(configfile)

            print("All done!")

        else:
            print("Conf file does not exist. Creating new file..")
            with open(config_file_path, "w"):
                pass
            print("Done!")
            check_api()
    except Exception as e:
        print(f"Errore: {e}")
