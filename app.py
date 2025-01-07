# Import necessary libraries
from flask import Flask, request, jsonify, render_template
import pymysql
import requests
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)

# Database connection details
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = 'root'
DB_NAME = 'cve_data'

# NVD CVE API details
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Initialize database connection
def get_db_connection():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME)

# Route to fetch CVEs from API and store in database
@app.route('/sync_cves', methods=['GET'])
def sync_cves():
    conn=None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch data from API
        params = {'startIndex': 0, 'resultsPerPage': 100}
        response = requests.get(BASE_URL, params=params).json()
        
        #print(response)
        for cve in response.get('vulnerabilities', []):
            cve_id = cve['cve']['id']
            description = cve['cve']['descriptions'][0]['value']
            identifier = cve['cve']['id']
            publisher_date = cve['cve']['published']
            last_modified = cve['cve']['lastModified']
            status = cve.get('vulnerabilities', {}).get('status', 'Active')
            score = (
                cve['cve'].get('metrics', {})
                .get('cvssMetricV2', [{}])[0]
                .get('cvssData', {})
                .get('baseScore', None)
            )


            # Insert into database
            cursor.execute(
                """
                INSERT INTO cve_info (
                    cve_id, identifier, description, base_score, publisher_date, last_modified, status
                ) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    description=VALUES(description), 
                    base_score=VALUES(base_score), 
                    publisher_date=VALUES(publisher_date),
                    last_modified=VALUES(last_modified),
                    status=VALUES(status)
                """,
                (cve_id, identifier, description, score, publisher_date, last_modified, status)
            )
        conn.commit()
        return jsonify({"message": "CVE data synchronized successfully."})

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        if conn:  # Close connection only if it exists
            conn.close()

# Route to get CVE details by ID
# Route to get CVE details by ID
@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_by_id(cve_id):
    conn = None  # Initialize conn variable
    try:
        conn = get_db_connection()  # Now it’s assigned here
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM cve_info WHERE cve_id = %s", (cve_id,))
        result = cursor.fetchone()

        # Fetch additional data from NVD API if CVE not found in DB
        if not result:
            result = fetch_cve_details_from_nvd(cve_id)
            if result is None:
                return f"CVE {cve_id} not found in NVD.", 404

            # Store new CVE data in the database (if required)
            cursor.execute(
                """
                INSERT INTO cve_info (
                    cve_id, identifier, description, base_score, publisher_date, last_modified, status
                ) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    description=VALUES(description), 
                    base_score=VALUES(base_score), 
                    publisher_date=VALUES(publisher_date),
                    last_modified=VALUES(last_modified),
                    status=VALUES(status)
                """,
                (cve_id, result['identifier'], result['description'], result['base_score'], 
                 result['publisher_date'], result['last_modified'], result['status'])
            )
            conn.commit()
        
        # Return the template with the CVE data
        return render_template('cve_detail.html', cve=result)

    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        if conn:  # Ensure conn is closed only if it was created
            conn.close()


# Helper function to fetch CVE details from the NVD API
def fetch_cve_details_from_nvd(cve_id):
    try:
        response = requests.get(f"{BASE_URL}/{cve_id}")
        if response.status_code == 200:
            data = response.json().get('result', {}).get('CVE_Items', [])[0]
            if data:
                # Print out the data to debug what the API is returning
                print(f"Fetched Data for {cve_id}: {data}")

                cve_details = {
                    'cve_id': data.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'N/A'),
                    'description': data.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'N/A'),
                    'severity': data.get('impact', {}).get('baseMetricV2', {}).get('severity', 'N/A'),
                    'base_score': data.get('impact', {}).get('baseMetricV2', {}).get('baseScore', 'N/A'),
                    'cvss_vector_string': data.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('vectorString', 'N/A'),
                    'exploitability_score': data.get('impact', {}).get('baseMetricV2', {}).get('exploitabilityScore', 'N/A'),
                    'impact_score': data.get('impact', {}).get('baseMetricV2', {}).get('impactScore', 'N/A'),
                    'cpe': [node.get('cpe23Uri', 'N/A') for node in data.get('configurations', {}).get('nodes', [{}])[0].get('cpe_match', [])],
                    'publisher_date': data.get('cve', {}).get('published', 'N/A'),
                    'last_modified': data.get('cve', {}).get('lastModified', 'N/A'),
                    'status': 'Active'  # You can modify the status based on additional logic if needed
                }

                # Debug the parsed cve_details data
                print(f"CVE Details: {cve_details}")

                return cve_details
            else:
                return None
        else:
            return None
    except Exception as e:
        print(f"Error fetching CVE {cve_id} from NVD: {e}")
        return None

# Route to filter CVEs by year
@app.route('/cves/year/<int:year>', methods=['GET'])
def get_cves_by_year(year):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        start_date = f"{year}-01-01"
        end_date = f"{year}-12-31"
        cursor.execute("SELECT * FROM cve_info WHERE last_modified BETWEEN %s AND %s", (start_date, end_date))
        results = cursor.fetchall()
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        conn.close()

# Route to filter CVEs by score
@app.route('/cves/score/<float:score>', methods=['GET'])
def get_cves_by_score(score):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM cve_info WHERE base_score = %s", (score,))
        results = cursor.fetchall()
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        conn.close()

# Route to render HTML page with CVE table
# Route to render HTML page with CVE table
@app.route('/cves/list', methods=['GET'])
def list_cves():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM cve_info")
        results = cursor.fetchall()
        #print("Fetched CVEs:", results)
        #return jsonify(results) 
        return render_template('cves.html',cves=results)  # Pass results to the HTML template
    except Exception as e:
        print(f"Error fetching CVEs: {e}")
        return jsonify({"error": str(e)})
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    get_db_connection()
    app.run(debug=True)
    
