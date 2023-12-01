import re
import os
import requests
import zipfile
import shutil
import datetime


def should_update():
    current_date = datetime.date.today()
    last_updated_date = None
    if not os.path.exists("db_temp"):
        return True
    if os.path.exists("last_updated_date.txt"):
        try:
            with open("last_updated_date.txt", "r") as file:
                last_updated_date = datetime.datetime.strptime(file.read().strip(), "%Y-%m-%d").date()
        except (ValueError, FileNotFoundError):
            last_updated_date = None
    if last_updated_date is None or current_date >= last_updated_date + datetime.timedelta(days=30):
        return True

    return False


def update():
    url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
    try:
        # Remove the existing update.zip if it exists
        if os.path.exists("update.zip"):
            os.remove("update.zip")
        print("downloading database")
        # Download the zip file
        response = requests.get(url)
        response.raise_for_status()

        # Save the zip file
        with open("update.zip", "wb") as file:
            file.write(response.content)

        # Remove the old extracted folder if it exists
        folder_name = "db_temp"
        folder_path = os.path.join(os.getcwd(), folder_name)

        # Check if the folder exists
        if os.path.exists(folder_path):
            # Remove the folder
            shutil.rmtree(folder_path)

        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Extract the contents of update.zip into the db_temp folder
        with zipfile.ZipFile("update.zip", "r") as zip_ref:
            zip_ref.extractall(folder_name)

        os.remove("update.zip")
        print("CVE database updated")
        return True

    except (requests.RequestException, zipfile.BadZipFile, OSError) as e:
        print(f"Error occurred while updating CVE database: {str(e)}")
        return False

def find_cve(text):
    try:
        # Update CVE database
        if should_update():
            updated = update()
            if updated:
                with open("last_updated_date.txt", "w") as file:
                    file.write(datetime.date.today().strftime("%Y-%m-%d"))
                print("CVE DB Update successful.")
            else:
                print("CVE DB Update failed. Retrying tomorrow.")

        with open("ignore.txt", "r") as file:
            ignore_dict = {}
            for line in file:
                words = line.strip().split()
                for word in words:
                    ignore_dict[word] = True

        content = text
        patterns =[]
        
        with open("regular_expression.txt", "r") as file:
            for line in file:
                pattern = line.strip()
                patterns.append(pattern)
                
        matches = []
        keywords = []
        key_map = {}
        print("using regular expression for finding softwares are  : ")
        for pattern in patterns:
            print(pattern)
            try : 
               matches.extend(re.findall(pattern, content, re.IGNORECASE | re.DOTALL))
            except : 
                print("wrong regular expression  : "+pattern)

        for match in matches:
            if match[0] not in ignore_dict:
                line = f"{match[0]} {match[1]}"
                keywords.append(line)

        local_repo_path = "db_temp"

        print("Scanning for vulnerabilities......")
        for key in keywords:
            key_map[key] = []

        for root, dirs, files in os.walk(local_repo_path):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    file_name = os.path.basename(file)
                    with open(file_path, 'r') as f:
                        if file_name != "metadata.json":
                            file_content = f.read()
                            # Iterate over keywords
                            for keyss in key_map:
                                if keyss in file_content:
                                    key_map[keyss].append(file_name)

        out = ""
        for keyword, file_paths in key_map.items():
            
            out += "Possible vulnerabilities of " + keyword + "\n"
            for file_path in file_paths:
                out += "  " + file_path + "\n"
        print("Done")
        return out
    except Exception as e:
        return "An error occurred:", str(e)

