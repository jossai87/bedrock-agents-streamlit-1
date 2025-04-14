import json
import sqlite3
import os
import boto3

# Use the database file that's packaged directly with the Lambda code
DB_FILE_PATH = 'company_database.db'

def lambda_handler(event, context):
    print(event)
    
    # Connect to the SQLite database that's included in the package
    conn = sqlite3.connect(DB_FILE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    def get_named_parameter(event, name):
        return next(item for item in event['parameters'] if item['name'] == name)['value']

    def companyResearch(event):
        company_name = get_named_parameter(event, 'name').lower()
        print("NAME PRINTED: ", company_name)
        
        # Direct query with case-insensitive search using LOWER function
        cursor.execute("SELECT * FROM companies WHERE LOWER(company_name) = ?", (company_name,))
        row = cursor.fetchone()
        
        if row:
            row_dict = dict(row)
            return {
                "companyId": row_dict["company_id"],
                "companyName": row_dict["company_name"],
                "industrySector": row_dict["industry_sector"],
                "revenue": row_dict["revenue"],
                "expenses": row_dict["expenses"],
                "profit": row_dict["profit"],
                "employees": row_dict["employees"]
            }
        
        return None
    
    def createPortfolio(event):
        num_companies = int(get_named_parameter(event, 'numCompanies'))
        industry = get_named_parameter(event, 'industry').lower()

        # Direct query with case-insensitive search and sorting
        cursor.execute("""
            SELECT * FROM companies 
            WHERE LOWER(industry_sector) = ? 
            ORDER BY profit DESC 
            LIMIT ?
        """, (industry, num_companies))
        
        rows = cursor.fetchall()
        
        companies = []
        for row in rows:
            row_dict = dict(row)
            companies.append({
                "companyId": row_dict["company_id"],
                "companyName": row_dict["company_name"],
                "industrySector": row_dict["industry_sector"],
                "revenue": row_dict["revenue"],
                "expenses": row_dict["expenses"],
                "profit": row_dict["profit"],
                "employees": row_dict["employees"]
            })
        
        return companies

    def sendEmail(event):
        email_address = get_named_parameter(event, 'emailAddress')
        fomc_summary = get_named_parameter(event, 'fomcSummary')
    
        # Retrieve the portfolio data as a string
        portfolio_data_string = get_named_parameter(event, 'portfolio')
    
        # Count companies in the database
        cursor.execute("SELECT COUNT(*) as count FROM companies")
        company_count = cursor.fetchone()['count']
        
        return f"Email sent successfully to {email_address} with portfolio information and FOMC summary. Database contains {company_count} companies."
        
    result = ''
    response_code = 200
    action_group = event['actionGroup']
    api_path = event['apiPath']
    
    print("api_path: ", api_path)
    
    if api_path == '/companyResearch':
        result = companyResearch(event)
    elif api_path == '/createPortfolio':
        result = createPortfolio(event)
    elif api_path == '/sendEmail':
        result = sendEmail(event)
    else:
        response_code = 404
        result = f"Unrecognized api path: {action_group}::{api_path}"
        
    # Close the database connection
    conn.close()
        
    response_body = {
        'application/json': {
            'body': result
        }
    }
        
    action_response = {
        'actionGroup': event['actionGroup'],
        'apiPath': event['apiPath'],
        'httpMethod': event['httpMethod'],
        'httpStatusCode': response_code,
        'responseBody': response_body
    }

    api_response = {'messageVersion': '1.0', 'response': action_response}
    return api_response