# Unware
Android Malware Detection Website
The use of modded APKs is increasing and people are downloading them without knowing whether their mobile phones are at risk. We will make some of many such malicious APKs and illustrate the kind of damage that will cause you. This project also includes the defense mechanism that needs to be approached to prevent these attacks from happening. This project includes a detailed security analysis of the malicious APK made.

# How to run
- clone the repo
- create virtual environment
    - python -m venv venv
    - venv/Scripts/activate (to activate environment in windows)
    - source venv/bin/activate (to activate environment in linux)
- install requirements
    - pip install -r requirements.txt
- now do migrations
    - python manage.py makemigrations
    - python manage.py migrate
- now run your django project
    - python manage.py runserver
