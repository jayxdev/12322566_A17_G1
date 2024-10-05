import csv
import re
import bcrypt
import requests
import sys
import os
import json
import datetime

# Constants
CSV_FILE = 'credential.csv'
MAX_ATTEMPTS = 5
NASA_API_KEY = 'e1RpWla4lDRmv2BtuznPbcheOm9c2nZzwLBbolRR'
NEO_FEED_URL = f'https://api.nasa.gov/neo/rest/v1/feed?api_key={NASA_API_KEY}'
#URL for the NASA SBDB API   
SSD_API_URL = 'https://api.le-systeme-solaire.net/rest/bodies/'
LIMIT = 5

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

def validate_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def validate_password(password):
    return len(password) >= 8 and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)

def read_csv():
    if not os.path.exists(CSV_FILE):
        open(CSV_FILE, 'w').close()
    with open(CSV_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        return list(reader)

def write_csv(data):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['email', 'password', 'security_question', 'ans'])
        writer.writeheader()
        writer.writerows(data)

def get_user(email):
    users = read_csv()
    for user in users:
        if user['email'] == email:
            return user
    return None

def login():
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        if not validate_email(email):
            print("Invalid email format.")
            continue

        user = get_user(email)
        if user and check_password(user['password'].encode('utf-8'), password):
            log(f"User {email} logged in successfully.")
            print("Login successful!")
            return True, email
        else:
            attempts += 1
            log(f"Invalid login attempt for {email}. Attempts remaining: {MAX_ATTEMPTS - attempts}")
            print("Invalid email or password. Attempts remaining:", MAX_ATTEMPTS - attempts)
            
    log(f"Too many failed login attempts for {email}. Exiting.")
    print("Too many failed attempts. Exiting.")
    sys.exit()

def sign_up():
    email = input("Enter your email: ")
    if not validate_email(email):
        print("Invalid email format.")
        return

    if get_user(email):
        print("Email already exists.")
        return

    password = input("Enter your password: ")
    if not validate_password(password):
        print("Password does not meet criteria.")
        print("Password must be at least 8 characters long and contain at least one special character.")
        return

    security_question = input("Enter a security question: ")
    ans= input("Enter the answer to the security question: ")
    users = read_csv()
    users.append({'email': email, 'password': hash_password(password).decode('utf-8'), 'security_question': security_question, 'ans': ans})
    write_csv(users)
    log(f"User {email} signed up successfully.")
    print("Sign up successful.")
    print("\n\nPlease login to continue.")
    if login():
        fetch_nasa_data()    

def reset_password():
    email = input("Enter your registered email: ")
    user = get_user(email)
    if not user:
        print("Email not found.")
        return

    answer = input(f"Answer the security question: \n{user['security_question']}: ")
    if answer.lower() == user['ans'].lower():
        new_password = input("Enter new password: ")
        if validate_password(new_password):
            user['password'] = hash_password(new_password).decode('utf-8')
            users = read_csv()
            for u in users:
                if u['email'] == email:
                    u['password'] = user['password']
            write_csv(users)
            log(f"Password reset successful for {email}.")
            print("Password reset successful.")
        else:
            print("Password does not meet criteria.")
    else:
        print("Incorrect answer to security question.")
        log(f"Incorrect answer to security question for {email}. Exiting.")

def fetch_nasa_data():
    try:
        response = requests.get(NEO_FEED_URL)
        response.raise_for_status()
        data = response.json()
        log("Fetched NASA data successfully.")
        with open('nasa_data.json', 'w') as f:
            json.dump(data, f, indent=4)
        if "near_earth_objects" not in data or not data["near_earth_objects"]:
            print("No near earth objects found.")
            return
        
        with open('near_earth.json', 'w') as f:
            json.dump(data["near_earth_objects"], f, indent=4)
        
        for neo in data["near_earth_objects"][list(data["near_earth_objects"].keys())[0]]:
            print(f'Name: {neo["name"]}')
            print(f'Close approach date: {neo["close_approach_data"][0]["close_approach_date"]}')
            print(f'Estimated diameter (meters): {neo["estimated_diameter"]["meters"]["estimated_diameter_max"]}')
            print(f'Velocity (km/h): {neo["close_approach_data"][0]["relative_velocity"]["kilometers_per_hour"]}')
            print(f'Miss distance (kilometers): {neo["close_approach_data"][0]["miss_distance"]["kilometers"]}')
            print(f'Hazardous: {neo["is_potentially_hazardous_asteroid"]}')
            print()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 403:
            print("Invalid or expired API key.")
            log("Invalid or expired API key.")
        else:
            print(f"HTTP error occurred: {http_err}")
            log(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError:
        print("Network error. Please check your internet connection.")
        log("Network error occurred.")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
        log(f"An error occurred: {err}")

def fetch_ssd_data(): 
    try:
        response = requests.get(SSD_API_URL)
        response.raise_for_status()
        data = response.json()
        print("Solar System Objects:")
        count = 0
        for obj in data['bodies']:
            if count >= LIMIT:
                break
            print(f"Name: {obj['englishName']}")
            print(f"Type: {obj['bodyType']}")
            print(f"Mass: {obj.get('mass', {}).get('massValue', 'N/A')} kg")
            print(f"Radius: {obj.get('meanRadius', 'N/A')} km")
            print(f"Discovered: {obj.get('discoveredBy', 'N/A')}")
            print("\n")
            count += 1
        log(f"Fetched Solar System data from NASA API")
    except Exception as e:
        log(f"Error fetching Solar System data: {e}")
        print(f"Error fetching Solar System data: {e}")


def menu(current_user):
    while True:
        print("1. Display Near Earth Objects\n2. Display Solar System Dynamics\n3. Logout/Main Menu")
        choice = input("Enter your choice: ")
        if choice == '1':
            print("Fetching NASA data...\n\n")
            fetch_nasa_data()
        elif choice == '2':
            print("Fetching Solar System data...\n\n")
            fetch_ssd_data()
        elif choice == '3':
            log(f"User {current_user} logged out.")
            break
        else:
            print("Invalid choice. Please try again.")        

def main():
    print("Welcome to the NASA Data Console")
    while True:
        choice = input("1. Login\n2. Sign Up\n3. Reset Password\n4. Exit\nChoose an option: ")
        if choice == '1':
            flag, email = login()
            if flag:
                menu(email)
        if choice == '2':
            sign_up()        
        elif choice == '3':
            reset_password()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

def log(message):
    message = f"{datetime.datetime.now()} - {message}"
    with open('application.log', 'a') as log_file:
        log_file.write(f"{message}\n")

if __name__ == "__main__":
    main()