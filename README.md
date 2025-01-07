CVE Management System
Overview
The CVE Management System is a web application that fetches Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API and stores it in a MySQL database. This system allows users to filter, view, and search CVE data based on various parameters like year, score, and individual CVE ID. Additionally, the application includes a front-end interface to display the CVE data in a user-friendly format.

Features:
Fetch and store CVE data from the NVD API.
Display CVE data in a user-friendly web interface.
View detailed information about specific CVEs.

Prerequisites:
Before running this application, ensure you have the following installed:
Python 3.x
MySQL Database
pymysql library
Flask framework
requests library

Installation:
Step 1: Set up MySQL Database
Create a MySQL database named cve_data:
sql
Copy code
CREATE DATABASE cve_data;
Create a table cve_info in the cve_data database to store the fetched CVE data:
sql
Copy code
CREATE TABLE cve_info (
    cve_id VARCHAR(50) PRIMARY KEY,
    identifier VARCHAR(50),
    description TEXT,
    base_score FLOAT,
    publisher_date DATETIME,
    last_modified DATETIME,
    status VARCHAR(20)
);

Step 2: Install Python Packages
Create a virtual environment (recommended):
bash
Copy code
python -m venv venv
source venv/bin/activate  # For Unix/macOS
venv\Scripts\activate  # For Windows
Install the required Python packages using pip:
bash
Copy code
pip install flask pymysql requests

Step 3: Configuration
Update the configuration values in the Flask application:

DB_HOST: The host for your MySQL database (e.g., 'localhost').
DB_USER: The user for your MySQL database (e.g., 'root').
DB_PASSWORD: The password for your MySQL user.
DB_NAME: The name of the MySQL database (cve_data).
Step 4: Run the Application
Once the setup is complete, you can run the Flask application using:

bash
Copy code
python app.py
The application will start on http://localhost:5000.


output:
syncronization of data
![1](https://github.com/user-attachments/assets/9a93cda4-6105-4a25-b18a-6a01d558988a)

CVE-List
![2 0](https://github.com/user-attachments/assets/cef6b3b8-3428-4922-b1c7-4fdddb5b4490)

CVE-id Details
![3](https://github.com/user-attachments/assets/abd8a03d-9e97-40d3-a1d5-d2105a4bd0b1)
